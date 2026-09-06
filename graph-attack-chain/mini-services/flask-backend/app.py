"""
Модуль app.py — главный входной точка Flask-бэкенда сервиса Graph Attack Chain.

================================================================================
НАЗНАЧЕНИЕ МОДУЛЯ
================================================================================
Данный модуль реализует REST API бэкенда для инструмента визуализации цепочек
кибератак (Graph Attack Chain). Сервис работает как API-прокси между фронтендом
(NEXT.js на порту 3000) и инфраструктурой безопасности Wazuh (API + Elasticsearch).

АРХИТЕКТУРНАЯ РОЛЬ
──────────────────
┌──────────┐    HTTP/JSON    ┌───────────────┐    Wazuh API    ┌──────────────┐
│ Frontend │ ──────────────> │  Flask API    │ ──────────────> │  Wazuh API   │
│ (Next.js)│ <────────────── │  (port 5001)  │ <────────────── │  (port 55000)│
└──────────┘                 └───────┬───────┘                 └──────────────┘
                                     │
                                     │ ES REST API
                                     ▼
                              ┌──────────────┐
                              │Elasticsearch │
                              │  (port 9200) │
                              └──────────────┘

Flask-бэкенд выполняет следующие функции:
1. Управление подключением к Wazuh API (JWT-аутентификация)
2. Управление подключением к Elasticsearch (Basic Auth)
3. Проксирование запросов к Wazuh API (агенты, алерты)
4. Запуск алгоритма построения графа цепочки атаки (через GraphEngine)
5. Предоставление данных о здоровье сервиса

ЭНДПОИНТЫ API
──────────────
- GET  /api/health         — проверка здоровья сервиса
- POST /api/wazuh/connect  — подключение к Wazuh API + Elasticsearch
- GET  /api/wazuh/status   — статус текущего подключения
- GET  /api/wazuh/agents   — список агентов Wazuh
- GET  /api/wazuh/alerts   — алерты конкретного агента
- POST /api/analyze        — анализ алерта и построение графа атаки

ЗАВИСИМОСТИ
───────────
- flask         : веб-фреймворк для REST API
- flask_cors    : обработка CORS-запросов от фронтенда
- wazuh_client  : клиент Wazuh API + Elasticsearch (WazuhClient)
- graph_engine  : движок построения графа цепочки атак (GraphEngine)

КОНФИГУРАЦИЯ
────────────
- Сервис запускается на порту 5001 (0.0.0.0)
- CORS разрешён для всех источников (для разработки)
- Логирование на уровне INFO с форматом: timestamp [LEVEL] message
"""

from __future__ import annotations

import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from wazuh_client import WazuhClient, WazuhConnectionError, WazuhAPIError
from graph_engine import GraphEngine

# --- Конфигурация приложения ---

# Создаём экземпляр Flask-приложения
app = Flask(__name__)

# Включаем CORS для всех маршрутов (необходимо для запросов от фронтенда Next.js,
# который работает на другом порту)
CORS(app)

# Настройка логирования: уровень INFO, формат с временной меткой и уровнем
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Глобальный клиент Wazuh — инициализируется при подключении через /api/wazuh/connect
# До подключения остаётся None
wazuh: WazuhClient | None = None

# Глобальный экземпляр графового движка — создаётся заново при каждом подключении
# к Wazuh, т.к. движок использует WazuhClient для запросов алертов
engine = GraphEngine()


# --- Маршруты API ---


@app.route("/api/health", methods=["GET"])
def health():
    """
    Проверка здоровья сервиса (Health Check).

    Эндпоинт для мониторинга доступности бэкенда. Возвращает статус сервиса,
    версию и информацию о подключении к Wazuh и Elasticsearch.

    Метод: GET
    Путь: /api/health

    Параметры запроса: нет

    Формат ответа (200 OK):
        {
            "status": "ok",                    # статус сервиса
            "service": "graph-attack-chain",   # название сервиса
            "version": "2.0.0",                # версия сервиса
            "wazuh_connected": true/false,      # подключён ли к Wazuh API
            "es_connected": true/false          # подключён ли к Elasticsearch
        }

    Возвращает:
        Response: JSON-объект с информацией о здоровье сервиса
    """
    return jsonify({
        "status": "ok",
        "service": "graph-attack-chain",
        "version": "2.0.0",
        "wazuh_connected": wazuh.connected if wazuh else False,
        "es_connected": wazuh.es_session is not None if wazuh else False,
    })


@app.route("/api/wazuh/connect", methods=["POST"])
def wazuh_connect():
    """
    Подключение к Wazuh API и Elasticsearch.

    Это основной эндпоинт для инициализации подключения к инфраструктуре
    безопасности. После успешного подключения глобальный объект WazuhClient
    используется всеми остальными эндпоинтами для запросов к Wazuh API и ES.

    Метод: POST
    Путь: /api/wazuh/connect

    Формат запроса (Content-Type: application/json):
        {
            "url": "https://192.168.1.50:55000",   # URL Wazuh API (обязательный)
            "username": "wazuh",                    # логин Wazuh API (обязательный)
            "password": "wazuh",                    # пароль Wazuh API (обязательный)
            "verify_ssl": false,                    # проверка SSL-сертификата (по умолч. false)
            "es_url": "https://192.168.1.50:9200",  # URL Elasticsearch (опциональный)
            "es_user": "admin",                     # логин ES (Basic Auth)
            "es_pass": "SecretPassword",            # пароль ES (Basic Auth)
            "es_verify_ssl": false                  # проверка SSL для ES
        }

    Формат ответа (200 OK):
        {
            "status": "ok",
            "version": "4.14.7",        # версия Wazuh API
            "url": "https://...",        # URL Wazuh API
            "es": {"status": "ok", "version": "8.x.x", "url": "..."},  # инфо об ES
            "agents_count": 5            # количество активных агентов
        }

    Ошибки:
        400 — пустой JSON или отсутствуют обязательные поля (url, username, password)
        503 — ошибка подключения к Wazuh (WazuhConnectionError)
        500 — внутренняя ошибка сервера

    Побочные эффекты:
        - Устанавливает глобальную переменную `wazuh` (WazuhClient)
        - Пересоздаёт глобальный `engine` (GraphEngine) с новым клиентом
        - Подключается к Elasticsearch (если указан es_url)
        - Запрашивает список активных агентов для подсчёта
    """
    global wazuh, engine

    # Парсим JSON-тело запроса (silent=True — не выбрасывать исключение при ошибке парсинга)
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Empty JSON body"}), 400

    # Извлекаем параметры подключения к Wazuh API
    url = body.get("url", "").rstrip("/")   # URL Wazuh API (убираем trailing /)
    username = body.get("username", "")      # Логин Wazuh
    password = body.get("password", "")      # Пароль Wazuh
    verify_ssl = body.get("verify_ssl", False)  # Проверка SSL (по умолч. выключена)

    # Извлекаем параметры подключения к Elasticsearch
    es_url = body.get("es_url", "")             # URL Elasticsearch
    es_user = body.get("es_user", "")            # Логин ES (Basic Auth)
    es_pass = body.get("es_pass", "")            # Пароль ES
    es_verify_ssl = body.get("es_verify_ssl", verify_ssl)  # SSL для ES (наследуем от Wazuh)

    # Проверяем обязательные параметры
    if not url or not username or not password:
        return jsonify({"error": "Укажите url, username и password"}), 400

    try:
        # Создаём экземпляр WazuhClient с параметрами подключения
        wazuh = WazuhClient(
            url=url, username=username, password=password, verify_ssl=verify_ssl,
            es_url=es_url, es_user=es_user, es_pass=es_pass, es_verify_ssl=es_verify_ssl,
        )

        # Подключаемся к Wazuh API (JWT-аутентификация)
        result = wazuh.connect()

        # Подключаемся к Elasticsearch для запросов алертов
        # (алерты запрашиваются из ES, а не из Wazuh API, т.к. /alerts/alerts недоступен)
        if es_url:
            es_result = wazuh.connect_es()
            result["es"] = es_result

        # Пересоздаём графовый движок с новым клиентом Wazuh
        # Движок использует WazuhClient для выполнения 6-шагового алгоритма поиска
        engine = GraphEngine(wazuh_client=wazuh)

        # Получаем список активных агентов для информационного ответа
        agents = wazuh.get_agents(status="active")
        result["agents_count"] = len(agents)

        logger.info(f"Connected to Wazuh at {url}, {len(agents)} active agents")
        return jsonify(result)

    except WazuhConnectionError as e:
        # Ошибка подключения к Wazuh или ES — сервис недоступен
        logger.error(f"Wazuh connection error: {e}")
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        # Непредвиденная ошибка — логируем с трейсбеком
        logger.exception("Wazuh connect error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/wazuh/status", methods=["GET"])
def wazuh_status():
    """
    Статус текущего подключения к Wazuh API и Elasticsearch.

    Позволяет фронтенду проверить, установлено ли подключение к инфраструктуре
    безопасности, без выполнения фактических запросов.

    Метод: GET
    Путь: /api/wazuh/status

    Формат ответа (200 OK):
        {
            "connected": true,           # подключён ли к Wazuh API (JWT-токен валиден)
            "es_connected": true,         # подключён ли к Elasticsearch (сессия активна)
            "url": "https://192...",       # URL Wazuh API
            "es_url": "https://192..."     # URL Elasticsearch
        }

    Если Wazuh не настроен (wazuh is None):
        {"connected": false, "message": "Wazuh не настроен"}
    """
    if not wazuh:
        return jsonify({"connected": False, "message": "Wazuh не настроен"})
    return jsonify({
        "connected": wazuh.connected,
        "es_connected": wazuh.es_session is not None,
        "url": wazuh.base_url,
        "es_url": wazuh.es_url,
    })


@app.route("/api/wazuh/agents", methods=["GET"])
def list_agents():
    """
    Получить список агентов из Wazuh.

    Агенты — это хосты, на которых установлен Wazuh Agent и которые
    отправляют логи/алерты на Wazuh Manager. Этот эндпоинт позволяет
    фронтенду отобразить список контролируемых хостов.

    Метод: GET
    Путь: /api/wazuh/agents

    Параметры запроса (Query String):
        status: фильтр по статусу агента
            - "active" (по умолчанию) — активные агенты
            - "disconnected" — отключённые
            - "never_connected" — никогда не подключавшиеся
            - "all" — все агенты

    Формат ответа (200 OK):
        {
            "agents": [
                {
                    "id": "001",                          # ID агента в Wazuh
                    "name": "WS-01",                       # имя хоста
                    "ip": "192.168.1.100",                 # IP-адрес
                    "status": "active",                    # статус
                    "os": "Windows",                       # ОС
                    "version": "v4.14.7",                  # версия агента
                    "last_keepalive": "2026-08-03T...",    # последнее время связи
                    "group": "default"                     # группа агента
                },
                ...
            ],
            "total": 5                     # общее количество агентов в ответе
        }

    Ошибки:
        503 — Wazuh не подключён
        500 — ошибка Wazuh API
    """
    if not wazuh or not wazuh.connected:
        return jsonify({"error": "Wazuh не подключён. Сначала вызовите /api/wazuh/connect"}), 503

    # Получаем параметр фильтра статуса из query string (по умолчанию "active")
    status = request.args.get("status", "active")
    try:
        # Запрашиваем агентов через WazuhClient → Wazuh API GET /agents
        agents = wazuh.get_agents(status=status)
        return jsonify({"agents": agents, "total": len(agents)})
    except WazuhAPIError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/wazuh/alerts", methods=["GET"])
def list_alerts():
    """
    Получить алерты (предупреждения безопасности) из Wazuh для указанного агента.

    Алерты — это события, обнаруженные правилами Wazuh (rule matches). Они
    запрашиваются напрямую из Elasticsearch (индекс wazuh-alerts-4.x-*), а не
    через Wazuh API, т.к. endpoint /alerts/alerts недоступен в Wazuh 4.14.7.

    Метод: GET
    Путь: /api/wazuh/alerts

    Параметры запроса (Query String):
        agent_id:     ID агента Wazuh (обязательный, например "001")
        limit:        макс. количество алертов (по умолчанию 50)
        severity_min: минимальный уровень серьёзности 0-15 (по умолчанию 0)
        hours:        за сколько последних часов искать (по умолчанию 24)

    Формат ответа (200 OK):
        {
            "alerts": [
                {
                    "event_id": "...",           # ID события
                    "timestamp": "2026-...",     # время события
                    "rule_id": "5716",           # ID правила Wazuh
                    "rule_description": "...",   # описание правила
                    "severity": 7,               # уровень серьёзности (0-15)
                    "agent_id": "001",           # ID агента
                    "agent_name": "WS-01",       # имя агента
                    "src_ip": "192.168.1.105",   # IP-источник
                    "dst_ip": "10.0.0.1",        # IP-назначение
                    "user_name": "admin",        # имя пользователя
                    "process_name": "ps.exe",    # имя процесса
                    "category": "process",       # категория алерта
                    "full_log": "..."            # полный лог события
                },
                ...
            ],
            "total": 123,                        # общее кол-во алертов в ES
            "agent_id": "001"                    # ID запрошенного агента
        }

    Ошибки:
        400 — не указан agent_id
        503 — Wazuh не подключён
        500 — ошибка при запросе алертов
    """
    if not wazuh or not wazuh.connected:
        return jsonify({"error": "Wazuh не подключён"}), 503

    # Обязательный параметр — ID агента
    agent_id = request.args.get("agent_id", "")
    if not agent_id:
        return jsonify({"error": "Укажите agent_id"}), 400

    # Опциональные параметры с значениями по умолчанию
    limit = int(request.args.get("limit", "50"))          # макс. кол-во результатов
    severity_min = int(request.args.get("severity_min", "0"))  # мин. severity
    hours = int(request.args.get("hours", "24"))          # временное окно в часах

    try:
        # Вычисляем начальную временную метку для запроса
        from datetime import datetime, timedelta, timezone
        from_time = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # Запрашиваем алерты из Elasticsearch через WazuhClient
        # ES-запрос фильтрует по: agent.id, @timestamp >= from_time, rule.level >= severity_min
        result = wazuh.get_alerts(
            agents=[agent_id],
            from_time=from_time,
            severity_min=severity_min,
            limit=limit,
        )

        # Форматируем каждый алерт в унифицированный формат для фронтенда
        # Метод get_alert_detail_for_graph извлекает поля из вложенной структуры Wazuh
        formatted = []
        for a in result["alerts"]:
            detail = wazuh.get_alert_detail_for_graph(a)
            formatted.append(detail)

        return jsonify({
            "alerts": formatted,
            "total": result["total"],
            "agent_id": agent_id,
        })
    except WazuhAPIError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logger.exception("Error fetching alerts")
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze", methods=["POST"])
def analyze_alert():
    """
    Анализ алерта и построение графа цепочки атаки.

    Это главный эндпоинт инструмента. Он принимает данные об исходном алерте
    безопасности и запускает 6-шаговый алгоритм поиска связанных событий,
    который строит граф цепочки атаки.

    АЛГОРИТМ АНАЛИЗА (реализован в GraphEngine.analyze_alert):
    ────────────────────────────────────────────────────────
    Шаг 0: Регистрация исходного алерта (узлы: хост, пользователь, IP, процесс)
    Шаг 1: Поиск событий аутентификации пользователя на хосте
    Шаг 2: Поиск сетевых соединений с хоста
    Шаг 3: Поиск связанных алертов (severity > 4) на том же хосте
    Шаг 4: Поиск событий с тем же IP на других хостах (латеральное движение)
    Шаг 5: Поиск событий, связанных с подозрительным процессом
    Шаг 6: Поиск подозрительных файловых операций

    Метод: POST
    Путь: /api/analyze

    Формат запроса (Content-Type: application/json):
        {
            "agent_id": "001",                       # ID агента Wazuh (обязательный)
            "agent_name": "WS-01",                   # имя агента
            "agent_ip": "192.168.1.100",             # IP-адрес агента
            "user_name": "admin",                    # подозрительный пользователь
            "process_name": "powershell.exe",        # подозрительный процесс
            "process_cmd": "-enc Base64...",         # командная строка процесса
            "src_ip": "192.168.1.105",               # IP-источник атаки
            "rule_id": "5716",                       # ID правила Wazuh
            "rule_description": "Suspicious PowerShell",  # описание правила
            "severity": 7,                           # уровень серьёзности (0-15)
            "category": "process",                   # категория алерта
            "full_log": "...",                       # полный лог события
            "time_window_min": 60                    # временное окно поиска (минуты)
        }

    Формат ответа (200 OK):
        {
            "nodes": [                  # узлы графа (сущности)
                {
                    "data": {
                        "id": "host-WS-01",       # уникальный ID узла
                        "label": "WS-01",          # отображаемое имя
                        "type": "host",            # тип узла (ip/host/user/process/file/domain)
                        "color": "#3b82f6",        # цвет узла (для визуализации)
                        "shape": "rectangle",      # форма узла
                        "typeLabel": "Хост"        # метка типа на русском
                    }
                },
                ...
            ],
            "edges": [                  # рёбра графа (связи между сущностями)
                {
                    "data": {
                        "id": "e-ip-192->host-WS-01-network",  # уникальный ID ребра
                        "source": "ip-192.168.1.105",           # исходный узел
                        "target": "host-WS-01",                 # целевой узел
                        "type": "network",                      # тип ребра
                        "label": "192.168.1.105 -> WS-01",     # отображаемая метка
                        "color": "#3b82f6",                     # цвет ребра
                        "dash": false,                           # пунктирная линия?
                        "rule_id": "5102",                       # ID правила
                        "severity": 7,                           # серьёзность
                        "timestamp": "2026-..."                  # время события
                    }
                },
                ...
            ],
            "stats": {                  # статистика графа
                "total_nodes": 12,      # общее кол-во узлов
                "total_edges": 15,      # общее кол-во рёбер
                "node_types": {"host": 3, "ip": 4, "user": 2, "process": 3},  # по типам
                "edge_types": {"network": 5, "auth": 3, "process": 7}         # по типам
            },
            "query_log": [              # лог выполнения запросов (для UI)
                {
                    "step": 1,          # номер шага
                    "name": "Поиск аутентификации",  # название шага
                    "description": "...",            # описание
                    "params": {"agent_id": "001"},   # параметры запроса
                    "results_count": 3,              # кол-во найденных результатов
                    "timestamp": "2026-..."          # время выполнения
                },
                ...
            ]
        }

    Ошибки:
        400 — Content-Type не application/json, пустой JSON, отсутствует agent_id
        503 — Wazuh не подключён
        500 — внутренняя ошибка при анализе
    """
    # Проверяем, что запрос содержит JSON
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    # Парсим JSON-тело запроса
    alert = request.get_json(silent=True)
    if not alert:
        return jsonify({"error": "Empty JSON"}), 400

    # Проверяем подключение к Wazuh
    if not wazuh or not wazuh.connected:
        return jsonify({"error": "Wazuh не подключён. Сначала вызовите /api/wazuh/connect"}), 503

    # Проверяем обязательные поля (минимум — agent_id)
    required = ["agent_id"]
    for f in required:
        if f not in alert or not alert[f]:
            return jsonify({"error": f"Missing required field: {f}"}), 400

    logger.info(f"Analyzing alert: agent={alert.get('agent_name', alert.get('agent_id'))}, user={alert.get('user_name', '')}")

    try:
        # Запускаем 6-шаговый алгоритм анализа через GraphEngine
        # Движок выполняет запросы к Wazuh/ES и строит граф {nodes, edges}
        result = engine.analyze_alert(alert)
        logger.info(f"Graph built: {result['stats']['total_nodes']} nodes, {result['stats']['total_edges']} edges")
        return jsonify(result)
    except WazuhConnectionError as e:
        # Потеряно подключение к Wazuh во время анализа
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        # Непредвиденная ошибка — логируем с трейсбеком
        logger.exception("Error analyzing alert")
        return jsonify({"error": str(e)}), 500


# --- Точка входа ---

if __name__ == "__main__":
    # Запуск Flask-сервера в режиме отладки на всех интерфейсах
    # В продакшене используется waitress WSGI сервер (см. start.py)
    logger.info("Starting Graph Attack Chain Backend v2.0 on port 5001")
    app.run(host="0.0.0.0", port=5001, debug=True)
