"""
Модуль graph_engine.py — ядро инструмента визуализации цепочек атак (Graph Attack Chain).

================================================================================
НАЗНАЧЕНИЕ МОДУЛЯ
================================================================================
Данный модуль реализует графовый движок, который строит визуализацию цепочки
кибератаки на основе алертов Wazuh. Движок выполняет 6-шаговый алгоритм
последовательного запроса к Wazuh API / Elasticsearch для обнаружения связанных
событий безопасности и формирует направленный граф {узлы, рёбра}.

АРХИТЕКТУРНАЯ РОЛЬ
──────────────────
graph_engine.py является центральным компонентом системы:

  app.py (Flask API)
       │
       ▼  вызов engine.analyze_alert(alert)
  graph_engine.py ──────> wazuh_client.py
       │                     │
       │                     ├── search_auth_events()      (Шаг 1)
       │                     ├── search_network_connections() (Шаг 2)
       │                     ├── search_related_alerts()   (Шаг 3)
       │                     ├── search_ip_on_other_hosts() (Шаг 4)
       │                     ├── search_process_events()   (Шаг 5)
       │                     └── search_file_events()      (Шаг 6)
       │
       ▼  результат: {nodes, edges, stats, query_log}
  Frontend (Cytoscape.js визуализация)

АЛГОРИТМ ПОСТРОЕНИЯ ГРАФА (6 ШАГОВ)
────────────────────────────────────
Шаг 0: Регистрация исходного алерта
  - Создаёт начальные узлы: хост, пользователь, IP-источник, процесс
  - Если нет agent_id, возвращает граф только из исходных данных

Шаг 1: Поиск аутентификации
  - ES-запрос: agent.id + rule.groups=*authentication* + пользователь
  - Назначение: выявить успешные/неуспешные входы подозрительного пользователя
  - Wazuh-поля: data.auth.user, data.srcuser, rule.groups (authentication)
  - Wazuh rule IDs: 5503, 5502, 5103, 5104

Шаг 2: Сетевые соединения
  - ES-запрос: agent.id + rule.groups=*(firewall|network)*
  - Назначение: обнаружить сетевую активность хоста (C2, exfil, lateral)
  - Wazuh-поля: srcip, dstip, srcport, dstport
  - Wazuh rule IDs: 5102, 5105, 5106

Шаг 3: Связанные алерты
  - ES-запрос: agent.id + rule.level > 4
  - Назначение: найти другие подозрительные события на том же хосте
  - Wazuh-поля: rule.level, rule.id, rule.description

Шаг 4: Латеральное движение (по IP)
  - ES-запрос: srcip = detected_src_ip AND agent.id ≠ текущий агент
  - Назначение: обнаружить движение атакующего на другие хосты с того же IP
  - Wazuh-поля: srcip, agent.id

Шаг 5: Анализ процесса
  - ES-запрос: agent.id + full_log содержит process_name
  - Назначение: найти все события, связанные с подозрительным процессом
  - Wazuh-поля: full_log (wildcard search)

Шаг 6: Файловые операции
  - ES-запрос: agent.id + rule.groups=*syscheck*
  - Назначение: обнаружить подозрительные изменения файлов (malware, persistence)
  - Wazuh-поля: data.syscheck.path, data.syscheck.event
  - Wazuh rule IDs: 554, 550, 553

ТИПЫ УЗЛОВ ГРАФА
────────────────
- ip:      IP-адрес (оранжевый ромб)       — сетевая сущность
- host:    Хост/агент (синий прямоугольник) — скомпрометированная машина
- user:    Пользователь (фиолетовый)         — аккаунт, использованный в атаке
- process: Процесс (красный гексагон)       — исполняемый файл/команда
- file:    Файл (зелёный треугольник)       — изменённый/созданный файл
- domain:  Домен (жёлтый эллипс)            — DNS-запрос (C2-домен)

ТИПЫ РЁБЕР ГРАФА
────────────────
- auth:     Аутентификация (фиолетовый пунктир)
- process:  Запуск процесса (красный сплошной)
- network:  Сетевое соединение (синий сплошной)
- file_op:  Файловая операция (зелёный пунктир)
- registry: Изменение реестра (оранжевый пунктир)
- dns:      DNS-запрос (жёлтый пунктир)

ЗАВИСИМОСТИ
───────────
- wazuh_client: WazuhClient — для запросов к Wazuh API и Elasticsearch
- re:            для извлечения DNS-доменов из full_log (регулярное выражение)
"""

import logging
import re
from typing import Optional
from wazuh_client import WazuhClient, WazuhConnectionError

logger = logging.getLogger(__name__)


# =====================================================================
#  Стили узлов графа — определяют визуальное представление каждого типа
#  Используются Cytoscape.js на фронтенде для рендеринга графа
# =====================================================================
NODE_STYLES = {
    "ip": {"color": "#f97316", "shape": "diamond", "label": "IP-адрес"},         # Оранжевый ромб — сетевой адрес
    "host": {"color": "#3b82f6", "shape": "rectangle", "label": "Хост"},          # Синий прямоугольник — хост/агент
    "user": {"color": "#8b5cf6", "shape": "round-rectangle", "label": "Пользователь"},  # Фиолетовый — аккаунт
    "process": {"color": "#ef4444", "shape": "hexagon", "label": "Процесс"},      # Красный гексагон — процесс
    "file": {"color": "#22c55e", "shape": "triangle", "label": "Файл"},           # Зелёный треугольник — файл
    "domain": {"color": "#eab308", "shape": "ellipse", "label": "Домен"},         # Жёлтый эллипс — DNS-домен
}

# =====================================================================
#  Стили рёбер графа — определяют визуальное представление связей
#  dash=True означает пунктирную линию (для логических связей)
# =====================================================================
EDGE_STYLES = {
    "auth": {"color": "#8b5cf6", "label": "Аутентификация", "dash": True},       # Фиолетовый пунктир
    "process": {"color": "#ef4444", "label": "Запуск процесса", "dash": False},   # Красный сплошной
    "network": {"color": "#3b82f6", "label": "Сетевое соединение", "dash": False}, # Синий сплошной
    "file_op": {"color": "#22c55e", "label": "Файловая операция", "dash": True},  # Зелёный пунктир
    "registry": {"color": "#f97316", "label": "Изменение реестра", "dash": True}, # Оранжевый пунктир
    "dns": {"color": "#eab308", "label": "DNS-запрос", "dash": True},            # Жёлтый пунктир
}


class GraphNode:
    """
    Узел направленного графа цепочки атаки.

    Представляет сущность безопасности (IP-адрес, хост, пользователь, процесс,
    файл или домен). Каждый узел имеет уникальный ID, отображаемую метку,
    тип и дополнительные детали.

    Атрибуты:
        id (str):       Уникальный идентификатор узла (например "ip-192.168.1.100")
        label (str):    Отображаемое имя узла (например "192.168.1.100")
        type (str):     Тип узла — один из: ip, host, user, process, file, domain
        details (dict): Дополнительные атрибуты (ip, command, full_path и т.д.)
    """

    def __init__(self, node_id, label, node_type, details=None):
        """
        Инициализировать узел графа.

        Параметры:
            node_id (str):       Уникальный ID узла в графе
            label (str):         Отображаемое имя (показывается на графике)
            node_type (str):     Тип узла (ip/host/user/process/file/domain)
            details (dict):      Дополнительные атрибуты (опционально)
        """
        self.id = node_id
        self.label = label
        self.type = node_type
        self.details = details or {}

    def to_dict(self):
        """
        Сериализовать узел в словарь для JSON-ответа API.

        Добавляет стилистические атрибуты (цвет, форма, метка типа) из
        NODE_STYLES на основе типа узла. Если тип не найден в словаре стилей,
        используются значения по умолчанию (серый, эллипс).

        Возвращает:
            dict: Словарь в формате Cytoscape.js: {"data": {id, label, type, color, shape, ...}}
        """
        style = NODE_STYLES.get(self.type, {})
        return {
            "data": {
                "id": self.id,
                "label": self.label,
                "type": self.type,
                "color": style.get("color", "#6b7280"),        # цвет узла (серый по умолчанию)
                "shape": style.get("shape", "ellipse"),         # форма узла (эллипс по умолчанию)
                "typeLabel": style.get("label", self.type),     # человекочитаемая метка типа
                **self.details,                                  # дополнительные атрибуты
            }
        }


class GraphEdge:
    """
    Ребро направленного графа цепочки атаки.

    Представляет связь/событие между двумя сущностями (например, "пользователь
    вошёл на хост", "IP подключился к IP", "процесс создал файл"). Каждое ребро
    содержит метаданные исходного алерта Wazuh (rule_id, severity, timestamp).

    Атрибуты:
        id (str):       Уникальный идентификатор ребра (например "e-host-A->proc-ps-network")
        source (str):   ID исходного узла
        target (str):   ID целевого узла
        type (str):     Тип ребра — один из: auth, process, network, file_op, registry, dns
        label (str):    Отображаемая метка ребра
        details (dict): Метаданные алерта (rule_id, severity, timestamp, full_log)
    """

    def __init__(self, edge_id, source, target, edge_type, label, details=None):
        """
        Инициализировать ребро графа.

        Параметры:
            edge_id (str):    Уникальный ID ребра
            source (str):     ID исходного узла (откуда)
            target (str):     ID целевого узла (куда)
            edge_type (str):  Тип ребра (auth/process/network/file_op/registry/dns)
            label (str):      Отображаемая метка (описание связи)
            details (dict):   Метаданные (rule_id, severity, timestamp, full_log)
        """
        self.id = edge_id
        self.source = source
        self.target = target
        self.type = edge_type
        self.label = label
        self.details = details or {}

    def to_dict(self):
        """
        Сериализовать ребро в словарь для JSON-ответа API.

        Добавляет стилистические атрибуты (цвет, метка типа, пунктир) из
        EDGE_STYLES на основе типа ребра.

        Возвращает:
            dict: Словарь в формате Cytoscape.js: {"data": {id, source, target, type, color, dash, ...}}
        """
        style = EDGE_STYLES.get(self.type, {})
        return {
            "data": {
                "id": self.id,
                "source": self.source,
                "target": self.target,
                "type": self.type,
                "label": self.label,
                "color": style.get("color", "#6b7280"),        # цвет ребра
                "typeLabel": style.get("label", self.type),     # метка типа на русском
                "dash": style.get("dash", False),               # пунктирная линия?
                **self.details,                                  # метаданные алерта
            }
        }


class GraphEngine:
    """
    Основной класс для построения графа цепочки атак.

    Реализует 6-шаговый алгоритм анализа алерта Wazuh, который последовательно
    запрашивает связанные события безопасности из Elasticsearch и строит
    направленный граф атаки.

    Экземпляр создаётся заново при каждом подключении к Wazuh (в app.py),
    т.к. движок должен иметь актуальную ссылку на WazuhClient.

    Атрибуты:
        client (WazuhClient):    Клиент Wazuh для запросов к API/ES
        nodes (dict):            Словарь узлов графа {node_id: GraphNode}
        edges (dict):            Словарь рёбер графа {edge_id: GraphEdge}
        query_log (list):        Лог выполнения запросов (для отображения в UI)
        _edge_counter (int):    Счётчик рёбер (для генерации уникальных ID)
    """

    def __init__(self, wazuh_client: Optional[WazuhClient] = None):
        """
        Инициализировать графовый движок.

        Параметры:
            wazuh_client (WazuhClient, optional): Клиент Wazuh для запросов.
                Если None, движок не сможет выполнять анализ (требуется подключение).
                Устанавливается при вызове /api/wazuh/connect в app.py.
        """
        self.client = wazuh_client
        self.nodes = {}  # id -> GraphNode — словарь узлов графа
        self.edges = {}  # id -> GraphEdge — словарь рёбер графа
        self.query_log = []  # лог выполнения запросов для UI
        self._edge_counter = 0  # счётчик для генерации уникальных ID рёбер

    def _add_node(self, node_id, label, node_type, **details):
        """
        Добавить узел в граф (если он ещё не существует).

        Метод идемпотентен — если узел с данным ID уже существует,
        он не будет создан заново (дубликаты игнорируются).

        Параметры:
            node_id (str):    Уникальный ID узла (например "ip-192.168.1.100")
            label (str):      Отображаемое имя узла
            node_type (str):  Тип узла (ip/host/user/process/file/domain)
            **details:        Дополнительные атрибуты узла

        Возвращает:
            GraphNode: Существующий или новосозданный узел
        """
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(node_id, label, node_type, details)
        return self.nodes[node_id]

    def _add_edge(self, source, target, edge_type, label, **details):
        """
        Добавить ребро в граф (если оно ещё не существует).

        Метод идемпотентен — если ребро с данным ID уже существует,
        оно не будет создано заново. ID ребра формируется из source,
        target и типа: "e-{source}->{target}-{edge_type}".

        Параметры:
            source (str):     ID исходного узла
            target (str):     ID целевого узла
            edge_type (str):  Тип ребра (auth/process/network/file_op/registry/dns)
            label (str):      Отображаемая метка ребра
            **details:        Метаданные (rule_id, severity, timestamp, full_log)

        Возвращает:
            GraphEdge: Существующее или новосозданное ребро
        """
        edge_id = f"e-{source}->{target}-{edge_type}"
        if edge_id not in self.edges:
            self._edge_counter += 1
            self.edges[edge_id] = GraphEdge(edge_id, source, target, edge_type, label, details)
        return self.edges[edge_id]

    def _log_query(self, query_name, query_desc, params, results_count):
        """
        Записать информацию о выполненном запросе в лог.

        Лог запросов отображается в правой панели фронтенда и позволяет
        SOC-аналитику видеть, какие шаги анализа были выполнены, какие
        параметры использовались и сколько результатов найдено.

        Параметры:
            query_name (str):      Название шага (например "Поиск аутентификации")
            query_desc (str):      Описание запроса
            params (dict):         Параметры запроса (agent_id, user и т.д.)
            results_count (int):   Количество найденных результатов
        """
        self.query_log.append({
            "step": len(self.query_log) + 1,  # порядковый номер шага (1-7)
            "name": query_name,
            "description": query_desc,
            "params": params,
            "results_count": results_count,
            "timestamp": self.client._time_ago(0) if self.client else "",  # текущее время в UTC
        })

    def _extract_from_alert(self, alert_detail: dict, query_label: str = ""):
        """
        Извлечь узлы и рёбра из унифицированного алерта Wazuh.

        Это центральный метод обработки алертов. Он анализирует поля алерта
        (IP, пользователь, процесс, файл, категория) и создаёт соответствующие
        узлы и рёбра в графе. Логика зависит от категории алерта:

        - authentication: создаёт рёбра IP→Host (аутентификация) и User→Host (вход)
        - network:       создаёт рёбра IP→IP (соединение) и Host→Domain (DNS)
        - process:       создаёт рёбра User→Process (запуск) и Host→Process (на хосте)
        - registry:      создаёт рёбра Process→File (изменение реестра)
        - file:          создаёт рёбра Process→File и User→File (файловые операции)

        Также извлекает DNS-домены из full_log с помощью регулярного выражения
        (ищет паттерны "query DOMAIN" или "querying DOMAIN").

        Параметры:
            alert_detail (dict): Унифицированный алерт от WazuhClient.get_alert_detail_for_graph()
                Ожидаемые ключи:
                - src_ip, dst_ip:        IP-адреса источника/назначения
                - agent_name, agent_ip:  имя и IP агента
                - user_name:             имя пользователя
                - process_name, process_cmd: имя и командная строка процесса
                - file_path, file_action: путь к файлу и действие (added/modified/deleted)
                - category:              категория алерта (authentication/network/process/registry/file)
                - rule_id, severity, timestamp, full_log, rule_description: метаданные
            query_label (str): Метка запроса (не используется, зарезервирована)
        """
        # --- Извлекаем поля из унифицированного алерта ---
        src_ip = alert_detail.get("src_ip")           # IP-источник (атакующий)
        dst_ip = alert_detail.get("dst_ip")           # IP-назначение (цель)
        agent_name = alert_detail.get("agent_name")   # имя агента (хоста)
        agent_ip = alert_detail.get("agent_ip")       # IP агента
        user_name = alert_detail.get("user_name")     # имя пользователя
        process_name = alert_detail.get("process_name")  # имя процесса
        process_cmd = alert_detail.get("process_cmd")    # командная строка
        file_path = alert_detail.get("file_path")     # путь к файлу
        file_action = alert_detail.get("file_action") # действие с файлом (added/modified)
        category = alert_detail.get("category", "process")  # категория алерта
        rule_id = alert_detail.get("rule_id", "")     # ID правила Wazuh
        severity = alert_detail.get("severity", 0)    # уровень серьёзности (0-15)
        timestamp = alert_detail.get("timestamp", "") # временная метка
        full_log = alert_detail.get("full_log", "")   # полный лог события
        rule_description = alert_detail.get("rule_description", "")  # описание правила

        # --- Создаём узлы графа на основе извлечённых полей ---

        # IP-источник — сетевая сущность (атакующий IP)
        if src_ip:
            self._add_node(f"ip-{src_ip}", src_ip, "ip")

        # IP-назначение — сетевая сущность (целевой IP)
        if dst_ip:
            self._add_node(f"ip-{dst_ip}", dst_ip, "ip")

        # Хост (агент) — скомпрометированная машина
        if agent_name:
            self._add_node(f"host-{agent_name}", agent_name, "host", ip=agent_ip)

        # Пользователь — аккаунт, использованный в атаке
        if user_name:
            self._add_node(f"user-{user_name}", user_name, "user")

        # Процесс — исполняемый файл/команда (подозрительный)
        if process_name:
            self._add_node(f"proc-{process_name}", process_name, "process", command=process_cmd)

        # Файл — изменённый/созданный/удалённый файл
        if file_path:
            # Для отображения используем только имя файла (последний компонент пути)
            short = file_path.split("\\")[-1] if "\\" in file_path else file_path.split("/")[-1]
            self._add_node(f"file-{file_path}", short, "file", full_path=file_path, action=file_action)

        # DNS-домен — извлекаем из full_log с помощью регулярного выражения
        # Ищет паттерны "query example.com" или "querying example.com" (Windows DNS events)
        if full_log:
            domain_match = re.search(r'(?:query|querying)[\s:]+(\S+)', full_log, re.IGNORECASE)
            if domain_match:
                domain = domain_match.group(1)
                self._add_node(f"domain-{domain}", domain, "domain")

        # --- Создаём рёбра графа в зависимости от категории алерта ---

        if category == "authentication":
            # Аутентификация: IP → Host (сетевой вход на хост)
            if src_ip and agent_name:
                self._add_edge(f"ip-{src_ip}", f"host-{agent_name}", "auth",
                    f"{rule_description}\n({src_ip} -> {agent_name})",
                    rule_id=rule_id, severity=severity, timestamp=timestamp, full_log=full_log)
            # Аутентификация: User → Host (пользователь вошёл на хост)
            if user_name and agent_name:
                self._add_edge(f"user-{user_name}", f"host-{agent_name}", "auth",
                    f"Вход: {user_name} -> {agent_name}",
                    rule_id=rule_id, severity=severity, timestamp=timestamp)

        elif category == "network":
            # Сетевое соединение: IP → IP (сетевой трафик)
            if src_ip and dst_ip:
                self._add_edge(f"ip-{src_ip}", f"ip-{dst_ip}", "network",
                    f"{src_ip} -> {dst_ip}",
                    rule_id=rule_id, severity=severity, timestamp=timestamp, full_log=full_log)
            # DNS-запрос: Host → Domain (если full_log содержит "DNS")
            if full_log and "DNS" in full_log.upper():
                domain_match = re.search(r'(?:query|querying)[\s:]+(\S+)', full_log, re.IGNORECASE)
                if domain_match:
                    domain = domain_match.group(1)
                    if agent_name:
                        self._add_edge(f"host-{agent_name}", f"domain-{domain}", "dns",
                            f"DNS: {domain}", rule_id=rule_id, severity=severity, timestamp=timestamp)

        elif category == "process":
            # Запуск процесса: User → Process (пользователь запустил процесс)
            if user_name and process_name:
                self._add_edge(f"user-{user_name}", f"proc-{process_name}", "process",
                    f"Запуск: {process_name}",
                    rule_id=rule_id, severity=severity, timestamp=timestamp, full_log=full_log)
            # Запуск процесса: Host → Process (процесс выполняется на хосте)
            if agent_name and process_name:
                self._add_edge(f"host-{agent_name}", f"proc-{process_name}", "process",
                    f"На {agent_name}: {process_name}",
                    rule_id=rule_id, severity=severity, timestamp=timestamp)

        elif category == "registry":
            # Изменение реестра: Process → File (процесс изменил ключ реестра)
            # file_path используется для пути к ключу реестра (HKLM\...\)
            if process_name and file_path:
                self._add_edge(f"proc-{process_name}", f"file-{file_path}", "registry",
                    f"Реестр: {file_path}",
                    rule_id=rule_id, severity=severity, timestamp=timestamp, full_log=full_log)

        elif category == "file":
            # Файловая операция: Process → File (процесс создал/изменил/удалил файл)
            if process_name and file_path:
                self._add_edge(f"proc-{process_name}", f"file-{file_path}", "file_op",
                    f"{file_action}: {file_path}",
                    rule_id=rule_id, severity=severity, timestamp=timestamp, full_log=full_log)
            # Файловая операция: User → File (пользователь выполнил операцию с файлом)
            if user_name and file_path:
                self._add_edge(f"user-{user_name}", f"file-{file_path}", "file_op",
                    f"{user_name}: {file_action} {file_path}",
                    rule_id=rule_id, severity=severity, timestamp=timestamp)

    def analyze_alert(self, alert_data: dict) -> dict:
        """
        Основной метод: анализ алерта и построение графа цепочки атаки.

        Выполняет 6-шаговый алгоритм последовательного запроса к Elasticsearch
        для обнаружения связанных событий безопасности. На каждом шаге
        результаты преобразуются в узлы и рёбра графа через _extract_from_alert().

        Порядок выполнения:
        ──────────────────
        1. Сброс графа (очистка узлов, рёбер, лога)
        2. Шаг 0: Регистрация исходного алерта (базовые узлы)
        3. Шаг 1: search_auth_events() — аутентификация
        4. Шаг 2: search_network_connections() — сетевые соединения
        5. Шаг 3: search_related_alerts() — связанные алерты
        6. Шаг 4: search_ip_on_other_hosts() — латеральное движение
        7. Шаг 5: search_process_events() — анализ процесса
        8. Шаг 6: search_file_events() — файловые операции
        9. Формирование результата через _build_result()

        Параметры:
            alert_data (dict): Данные анализируемого алерта. Ожидаемые ключи:
                - alert_id:           ID алерта в Wazuh (если есть)
                - agent_id:           ID агента Wazuh (например "001") — ОБЯЗАТЕЛЬНЫЙ
                - agent_name:         имя агента (например "WS-01")
                - agent_ip:           IP-адрес агента
                - user_name:          подозрительный пользователь
                - process_name:       подозрительный процесс
                - src_ip:             IP-источник атаки
                - rule_id:            ID правила Wazuh
                - rule_description:   описание правила
                - severity:           уровень серьёзности (0-15)
                - category:           категория алерта
                - full_log:           полный лог события
                - time_window_min:    временное окно поиска в минутах (по умолчанию 60)

        Возвращает:
            dict: Результат анализа в формате:
                {
                    "nodes": [...],      # список узлов графа
                    "edges": [...],      # список рёбер графа
                    "stats": {...},      # статистика (кол-во узлов/рёбер по типам)
                    "query_log": [...]   # лог выполнения запросов
                }

        Выбрасывает:
            WazuhConnectionError: если Wazuh не подключён
        """
        # Проверяем, что клиент Wazuh подключён
        if not self.client or not self.client.connected:
            raise WazuhConnectionError("Wazuh не подключён")

        # ===== Сброс состояния графа перед новым анализом =====
        self.nodes = {}
        self.edges = {}
        self.query_log = []
        self._edge_counter = 0

        # ===== Извлекаем параметры исходного алерта =====
        agent_id = alert_data.get("agent_id", "")           # ID агента (ключевой параметр)
        agent_name = alert_data.get("agent_name", "")       # имя хоста
        agent_ip = alert_data.get("agent_ip", "")           # IP хоста
        user_name = alert_data.get("user_name", "")         # подозрительный пользователь
        process_name = alert_data.get("process_name", "")   # подозрительный процесс
        src_ip = alert_data.get("src_ip", "")               # IP-источник атаки
        rule_description = alert_data.get("rule_description", "Анализируемый алерт")
        time_window = alert_data.get("time_window_min", 60) # временное окно (минуты)

        # ===== Шаг 0: Исходный алерт — создаём базовые узлы =====
        # Эти узлы представляют сущности, упомянутые в исходном алерте,
        # который инициировал анализ
        if agent_name:
            self._add_node(f"host-{agent_name}", agent_name, "host", ip=agent_ip)
        if user_name:
            self._add_node(f"user-{user_name}", user_name, "user")
        if src_ip:
            self._add_node(f"ip-{src_ip}", src_ip, "ip")
        if process_name:
            self._add_node(f"proc-{process_name}", process_name, "process",
                command=alert_data.get("process_cmd", ""))

        # Логируем исходный алерт как шаг 0
        self._log_query("Исходный алерт", f"Анализ: {rule_description}",
            {"agent": agent_name, "user": user_name, "process": process_name}, 1)

        # Если нет ID агента, невозможно выполнить запросы к ES —
        # возвращаем граф только из исходных данных
        if not agent_id:
            return self._build_result(alert_data)

        # ===== Запрос 1: Аутентификация =====
        # Поиск событий входа/выхода пользователя на хосте.
        # ES-запрос: agent.id + rule.groups=*authentication* + пользователь
        # Wazuh-поля: data.auth.user, data.srcuser
        # Wazuh rule IDs: 5503 (success), 5502 (failed), 5103, 5104
        try:
            auth_alerts = self.client.search_auth_events(agent_id, user_name, time_window)
            for a in auth_alerts:
                detail = self.client.get_alert_detail_for_graph(a)
                self._extract_from_alert(detail)
            self._log_query("Поиск аутентификации",
                f"Входы '{user_name}' на {agent_name} за {time_window} мин",
                {"agent_id": agent_id, "user": user_name}, len(auth_alerts))
        except Exception as e:
            logger.warning(f"Query 1 failed: {e}")
            self._log_query("Поиск аутентификации", f"Ошибка: {str(e)}", {}, 0)

        # Определяем IP-источник атаки: сначала берём из исходного алерта,
        # если нет — из первого найденного события аутентификации
        detected_src_ip = src_ip
        if not detected_src_ip and auth_alerts:
            for a in auth_alerts:
                d = self.client.get_alert_detail_for_graph(a)
                if d.get("src_ip"):
                    detected_src_ip = d["src_ip"]
                    break

        # ===== Запрос 2: Сетевые соединения =====
        # Поиск сетевой активности хоста (firewall, network events).
        # ES-запрос: agent.id + rule.groups=*(firewall|network)*
        # Wazuh-поля: srcip, dstip, srcport, dstport
        # Wazuh rule IDs: 5102, 5105, 5106
        try:
            net_alerts = self.client.search_network_connections(agent_id, time_window)
            for a in net_alerts:
                detail = self.client.get_alert_detail_for_graph(a)
                self._extract_from_alert(detail)
            self._log_query("Сетевые соединения",
                f"Соединения с {agent_name} за {time_window} мин",
                {"agent_id": agent_id}, len(net_alerts))
        except Exception as e:
            logger.warning(f"Query 2 failed: {e}")
            self._log_query("Сетевые соединения", f"Ошибка: {str(e)}", {}, 0)

        # ===== Запрос 3: Связанные алерты =====
        # Поиск других подозрительных алертов на том же хосте.
        # ES-запрос: agent.id + rule.level > 4 (severity threshold)
        # Помогает обнаружить escalation, persistence и другие аномалии
        try:
            related_alerts = self.client.search_related_alerts(agent_id, severity_min=4, time_window_min=time_window)
            for a in related_alerts:
                detail = self.client.get_alert_detail_for_graph(a)
                self._extract_from_alert(detail)
            self._log_query("Связанные алерты",
                f"Другие алерты на {agent_name} (severity>4)",
                {"agent_id": agent_id}, len(related_alerts))
        except Exception as e:
            logger.warning(f"Query 3 failed: {e}")
            self._log_query("Связанные алерты", f"Ошибка: {str(e)}", {}, 0)

        # ===== Запрос 4: Латеральное движение =====
        # Поиск событий с тем же IP-источником на ДРУГИХ хостах.
        # ES-запрос: srcip = detected_src_ip AND agent.id ≠ текущий
        # Ключевой индикатор lateral movement: атакующий IP появился на другой машине
        # Выполняется только если удалось определить IP-источник
        if detected_src_ip:
            try:
                lateral_alerts = self.client.search_ip_on_other_hosts(detected_src_ip, agent_id, time_window)
                for a in lateral_alerts:
                    detail = self.client.get_alert_detail_for_graph(a)
                    self._extract_from_alert(detail)
                self._log_query("Латеральное движение",
                    f"События с IP {detected_src_ip} на других хостах",
                    {"src_ip": detected_src_ip, "exclude": agent_id}, len(lateral_alerts))
            except Exception as e:
                logger.warning(f"Query 4 failed: {e}")
                self._log_query("Латеральное движение", f"Ошибка: {str(e)}", {}, 0)

        # ===== Запрос 5: Анализ процесса =====
        # Поиск всех событий, связанных с подозрительным процессом.
        # ES-запрос: agent.id + full_log содержит process_name (wildcard)
        # Помогает обнаружить chain of execution: parent→child процессы
        # Выполняется только если указано имя процесса
        if process_name:
            try:
                proc_alerts = self.client.search_process_events(agent_id, process_name, time_window)
                for a in proc_alerts:
                    detail = self.client.get_alert_detail_for_graph(a)
                    self._extract_from_alert(detail)
                self._log_query("Анализ процесса",
                    f"События {process_name} на {agent_name}",
                    {"agent_id": agent_id, "process": process_name}, len(proc_alerts))
            except Exception as e:
                logger.warning(f"Query 5 failed: {e}")
                self._log_query("Анализ процесса", f"Ошибка: {str(e)}", {}, 0)

        # ===== Запрос 6: Файловые операции =====
        # Поиск подозрительных изменений файлов (syscheck events).
        # ES-запрос: agent.id + rule.groups=*syscheck*
        # Wazuh-поля: data.syscheck.path, data.syscheck.event
        # Wazuh rule IDs: 554 (added), 550 (modified), 553 (deleted)
        # Помогает обнаружить malware droppers, persistence mechanisms, data theft
        try:
            file_alerts = self.client.search_file_events(agent_id, time_window)
            for a in file_alerts:
                detail = self.client.get_alert_detail_for_graph(a)
                self._extract_from_alert(detail)
            self._log_query("Файловые операции",
                f"Подозрительные файловые операции на {agent_name}",
                {"agent_id": agent_id}, len(file_alerts))
        except Exception as e:
            logger.warning(f"Query 6 failed: {e}")
            self._log_query("Файловые операции", f"Ошибка: {str(e)}", {}, 0)

        # Формируем итоговый результат
        return self._build_result(alert_data)

    def _build_result(self, initial_alert: dict) -> dict:
        """
        Сформировать итоговый результат анализа графа.

        Сериализует все узлы и рёбра в формат Cytoscape.js, вычисляет
        статистику (количество узлов/рёбер по типам) и возвращает
        полный результат для отправки на фронтенд.

        Параметры:
            initial_alert (dict): Исходный алерт (не используется напрямую,
                зарезервирован для будущих расширений)

        Возвращает:
            dict: Результат в формате:
                {
                    "nodes": [
                        {"data": {"id": "...", "label": "...", "type": "...", ...}},
                        ...
                    ],
                    "edges": [
                        {"data": {"id": "...", "source": "...", "target": "...", ...}},
                        ...
                    ],
                    "stats": {
                        "total_nodes": int,        # общее кол-во узлов
                        "total_edges": int,        # общее кол-во рёбер
                        "node_types": {"ip": N, "host": M, ...},  # кол-во по типам
                        "edge_types": {"auth": N, "network": M, ...}  # кол-во по типам
                    },
                    "query_log": [...]  # лог выполнения запросов
                }
        """
        # Сериализуем узлы и рёбра в формат Cytoscape.js
        nodes_list = [n.to_dict() for n in self.nodes.values()]
        edges_list = [e.to_dict() for e in self.edges.values()]

        # Вычисляем статистику по типам узлов
        node_types = {}
        for n in self.nodes.values():
            node_types[n.type] = node_types.get(n.type, 0) + 1

        # Вычисляем статистику по типам рёбер
        edge_types = {}
        for e in self.edges.values():
            edge_types[e.type] = edge_types.get(e.type, 0) + 1

        return {
            "nodes": nodes_list,
            "edges": edges_list,
            "stats": {
                "total_nodes": len(nodes_list),
                "total_edges": len(edges_list),
                "node_types": node_types,
                "edge_types": edge_types,
            },
            "query_log": self.query_log,
        }
