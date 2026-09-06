"""
Модуль wazuh_client.py — клиент для взаимодействия с Wazuh API и Elasticsearch.

================================================================================
НАЗНАЧЕНИЕ МОДУЛЯ
================================================================================
Данный модуль реализует клиент для двух источников данных:
1. Wazuh Manager API (порт 55000) — для управления агентами и аутентификации
2. Elasticsearch (порт 9200) — для поиска алертов в индексе wazuh-alerts-4.x-*

Алерты запрашиваются НЕ через Wazuh API (endpoint /alerts/alerts), а напрямую
из Elasticsearch, т.к. данный endpoint недоступен в Wazuh 4.14.7.

АРХИТЕКТУРНАЯ РОЛЬ
──────────────────
wazuh_client.py — нижний уровень стека, обеспечивает доступ к данным:

  app.py (Flask API)
       │
       ▼
  graph_engine.py
       │
       ▼  вызывает методы WazuhClient
  wazuh_client.py
       │
       ├──→ Wazuh Manager API (JWT Auth) — агенты, версия, health
       │       POST /security/user/authenticate?raw=true  → JWT-токен
       │       GET  /agents?status=active&select=...      → список агентов
       │       GET  /?pretty=true                         → версия API
       │
       └──→ Elasticsearch (Basic Auth) — алерты
               POST /wazuh-alerts-4.x-*/_search  → DSL query → hits

МЕТОДЫ ДЛЯ ПОСТРОЕНИЯ ГРАФА (6-шаговый алгоритм)
──────────────────────────────────────────────────
1. search_auth_events()         — аутентификация (rule.groups=*authentication*)
2. search_network_connections()  — сетевые соединения (rule.groups=*firewall*,*network*)
3. search_related_alerts()      — связанные алерты (rule.level > N)
4. search_ip_on_other_hosts()   — латеральное движение (srcip + другой agent.id)
5. search_process_events()      — события процесса (wildcard по full_log)
6. search_file_events()         — файловые операции (rule.groups=*syscheck*)

ПАРСЕР WAZUH QUERY STRING
─────────────────────────
Модуль также реализует парсер Wazuh query string (параметр q) для преобразования
в Elasticsearch bool query. Поддерживаемые операторы:
  =   → term query          (agent.id=001)
  !=  → must_not + term     (status!=active)
  >   → range gt            (rule.level>5)
  >=  → range gte           (rule.level>=5)
  <   → range lt            (rule.level<10)
  <=  → range lte           (rule.level<=10)
  ~   → wildcard            (rule.description~power)
  ~=  → wildcard            (rule.description~=shell)
  |   → OR (should)         (rule.id=5502|rule.id=5503)
  AND → AND (must)          (agent.id=001 AND rule.level>5)

ИСТОЧНИКИ ДАННЫХ И WAZUH-ПОЛЯ
──────────────────────────────
- Wazuh API (управление):
    /agents → {id, name, ip, status, version, lastKeepAlive, os, group}

- Elasticsearch (алерты, индекс wazuh-alerts-4.x-*):
    @timestamp           — время события
    agent.id             — ID агента (например "001")
    agent.name           — имя агента (например "WS-01")
    agent.ip             — IP-адрес агента
    rule.id              — ID правила Wazuh (например "5716")
    rule.level           — уровень серьёзности (0-15)
    rule.description     — описание правила
    rule.groups          — группы правил (authentication, syscheck, etc.)
    data.srcip           — IP-источник
    data.dstip           — IP-назначение
    data.srcport         — порт источника
    data.dstport         — порт назначения
    data.auth.user       — пользователь аутентификации
    data.srcuser         — исходный пользователь (sudo)
    data.win.eventdata.image       — путь к исполняемому файлу (Windows)
    data.win.eventdata.commandLine — командная строка (Windows)
    data.win.eventdata.targetUserName — целевой пользователь (Windows)
    data.win.eventdata.targetFilename — целевой файл (Windows)
    data.win.eventdata.actionType    — тип действия (Windows)
    data.syscheck.path   — путь к файлу (syscheck/FIM)
    data.syscheck.event  — событие syscheck (added/modified/deleted)
    full_log             — полный текст лога
    srcip, dstip         — IP-адреса (верхний уровень, для некоторых алертов)

ЗАВИСИМОСТИ
───────────
- requests:    HTTP-клиент для запросов к Wazuh API и Elasticsearch
- urllib3:     отключение SSL-предупреждений (verify_ssl=False)
- datetime:    вычисление временных окон для ES-запросов

ССЫЛКИ
──────
- Wazuh API документация: https://documentation.wazuh.com/current/api-reference.html
- Elasticsearch DSL:      https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html
"""

import logging
import requests
import urllib3
from datetime import datetime, timedelta, timezone
from typing import Optional

# Отключаем предупреждения urllib3 о ненадёжном SSL-соединении
# (используется verify_ssl=False для самоподписанных сертификатов Wazuh/ES)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class WazuhConnectionError(Exception):
    """
    Исключение — ошибка подключения к Wazuh API или Elasticsearch.

    Выбрасывается когда:
    - Wazuh API недоступен (ConnectionError, Timeout)
    - Неверные учётные данные (401 Unauthorized)
    - Elasticsearch недоступен
    - Токен JWT не получен/просрочен
    """
    pass


class WazuhAPIError(Exception):
    """
    Исключение — ошибка выполнения запроса к Wazuh API или Elasticsearch.

    Выбрасывается когда:
    - Wazuh API вернул ошибку (не 2xx)
    - Elasticsearch вернул ошибку поиска
    - Некорректные параметры запроса
    """
    pass


class WazuhClient:
    """
    Клиент для работы с Wazuh Manager API и Elasticsearch.

    Обеспечивает два канала связи:
    1. Wazuh API (JWT-аутентификация) — управление агентами, получение версии
    2. Elasticsearch (Basic Auth) — поиск алертов в wazuh-alerts-4.x-*

    Жизненный цикл:
    ──────────────
    1. Создание:   WazuhClient(url=..., username=..., password=..., es_url=...)
    2. Подключение: connect()  → JWT-токен + версия API
    3. ES:          connect_es() → сессия Elasticsearch
    4. Работа:      get_agents(), get_alerts(), search_*()
    5. Отключение:  disconnect()

    Автообновление токена:
    ─────────────────────
    Если Wazuh API возвращает 401 (токен просрочен), _api_get() автоматически
    вызывает connect() для обновления JWT-токена и повторяет запрос.

    Атрибуты:
        base_url (str):               URL Wazuh API (например "https://192.168.1.50:55000")
        username (str):               Логин Wazuh API
        password (str):               Пароль Wazuh API
        verify_ssl (bool):            Проверка SSL-сертификата
        api_port (int):               Порт Wazuh API (по умолчанию 55000)
        token (str|None):             JWT-токен Wazuh API
        session (requests.Session):   HTTP-сессия для Wazuh API (с Bearer token)
        _connected (bool):            Флаг подключения к Wazuh API
        es_url (str):                 URL Elasticsearch
        es_user (str):                Логин Elasticsearch (Basic Auth)
        es_pass (str):                Пароль Elasticsearch
        es_verify_ssl (bool):         Проверка SSL для Elasticsearch
        es_session (requests.Session|None): HTTP-сессия для Elasticsearch
    """

    # Таймаут HTTP-запросов по умолчанию (секунды)
    DEFAULT_TIMEOUT = 30

    def __init__(self, url: str = "", username: str = "", password: str = "",
                 verify_ssl: bool = False, api_port: int = 55000,
                 es_url: str = "", es_user: str = "", es_pass: str = "",
                 es_verify_ssl: bool = False):
        """
        Инициализировать клиент Wazuh.

        Параметры:
            url (str):          URL Wazuh API (например "https://192.168.1.50:55000")
            username (str):     Логин Wazuh API (по умолчанию "wazuh")
            password (str):     Пароль Wazuh API
            verify_ssl (bool):  Проверять ли SSL-сертификат (False для self-signed)
            api_port (int):     Порт Wazuh API (обычно 55000)
            es_url (str):       URL Elasticsearch (например "https://192.168.1.50:9200")
            es_user (str):      Логин Elasticsearch (по умолчанию "admin")
            es_pass (str):      Пароль Elasticsearch
            es_verify_ssl (bool): Проверять ли SSL для ES (наследует verify_ssl если не указан)
        """
        # --- Параметры Wazuh API ---
        self.base_url = url.rstrip("/")     # URL Wazuh API (убираем trailing /)
        self.username = username            # Логин Wazuh
        self.password = password            # Пароль Wazuh
        self.verify_ssl = verify_ssl        # Проверка SSL
        self.api_port = api_port            # Порт API (55000)
        self.token: Optional[str] = None    # JWT-токен (устанавливается после connect())
        self.session = requests.Session()   # HTTP-сессия для Wazuh API
        self.session.verify = verify_ssl    # SSL-проверка для сессии
        self._connected = False             # Флаг успешного подключения

        # --- Параметры Elasticsearch ---
        self.es_url = es_url.rstrip("/") if es_url else ""  # URL ES
        self.es_user = es_user              # Логин ES (Basic Auth)
        self.es_pass = es_pass              # Пароль ES
        self.es_verify_ssl = es_verify_ssl  # SSL-проверка для ES
        self.es_session: Optional[requests.Session] = None  # HTTP-сессия ES (после connect_es())

    @property
    def connected(self) -> bool:
        """
        Проверить, подключён ли клиент к Wazuh API.

        Возвращает:
            bool: True, если JWT-токен получен и флаг подключения установлен
        """
        return self._connected and self.token is not None

    # ============================================================
    #  Подключение к Wazuh API (управление агентами, аутентификация)
    # ============================================================

    def connect(self) -> dict:
        """
        Подключиться к Wazuh Manager API и получить JWT-токен.

        Использует метод аутентификации GET + Basic Auth + ?raw=true —
        единственный метод, проверенно работающий с Wazuh 4.14.7.
        Параметр ?raw=true заставляет API возвращать токен как plain text
        вместо JSON-обёртки.

        После успешной аутентификации:
        1. JWT-токен сохраняется в self.token
        2. Bearer token добавляется в заголовки HTTP-сессии
        3. Запрашивается версия Wazuh API через GET /

        Возвращает:
            dict: Результат подключения:
                {
                    "status": "ok",
                    "version": "4.14.7",    # версия Wazuh API
                    "url": "https://..."     # URL Wazuh API
                }

        Выбрасывает:
            WazuhConnectionError: при ошибке подключения (ConnectionError, Timeout, 401 и т.д.)
        """
        # URL аутентификации Wazuh API
        # ?raw=true — возвращает токен как plain text (не JSON)
        auth_url = f"{self.base_url}/security/user/authenticate?raw=true"

        try:
            # GET-запрос с Basic Auth — проверенный рабочий метод для Wazuh 4.14.7
            resp = self.session.get(
                auth_url,
                auth=(self.username, self.password),
                timeout=self.DEFAULT_TIMEOUT,
            )
            resp.raise_for_status()

            # Парсим ответ — raw=true возвращает токен как plain text
            token_text = resp.text.strip()
            if token_text and len(token_text) > 20:
                # Токен выглядит как JWT (длинная строка с точками)
                self.token = token_text
            else:
                # Попробуем парсить как JSON (на случай другой конфигурации Wazuh)
                try:
                    data = resp.json()
                    if isinstance(data, str):
                        self.token = data
                    elif data.get("data", {}).get("token"):
                        self.token = data["data"]["token"]
                    else:
                        raise WazuhConnectionError("Не удалось получить токен из ответа Wazuh")
                except ValueError:
                    raise WazuhConnectionError(f"Неожиданный формат ответа: {token_text[:100]}")

            # Добавляем Bearer token в заголовки сессии для последующих запросов
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            self._connected = True

            # Запрашиваем информацию о Wazuh API (версия)
            info = self._api_get("/", params={"pretty": "true"})
            # api_version — поле из ответа /?pretty=true (не "version"!)
            version = info.get("data", {}).get("api_version") or info.get("data", {}).get("version", "unknown")

            logger.info(f"Connected to Wazuh {version} at {self.base_url}")
            return {
                "status": "ok",
                "version": version,
                "url": self.base_url,
            }

        except requests.exceptions.ConnectionError:
            raise WazuhConnectionError(
                f"Не удалось подключиться к {self.base_url}. "
                f"Проверьте, что Wazuh API запущен на этом адресе."
            )
        except requests.exceptions.Timeout:
            raise WazuhConnectionError(f"Таймаут подключения к {self.base_url}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise WazuhConnectionError("Неверный логин или пароль Wazuh")
            raise WazuhConnectionError(f"HTTP ошибка: {e.response.status_code}")
        except Exception as e:
            raise WazuhConnectionError(f"Ошибка подключения: {str(e)}")

    def connect_es(self) -> dict:
        """
        Подключиться к Elasticsearch и проверить доступность.

        Создаёт отдельную HTTP-сессию с Basic Auth для запросов к ES.
        Проверяет, что ES доступен, запрашивая корневой endpoint "/".

        Elasticsearch используется для поиска алертов в индексе
        wazuh-alerts-4.x-* (вместо Wazuh API /alerts/alerts, который
        недоступен в Wazuh 4.14.7).

        Возвращает:
            dict: Результат подключения:
                {
                    "status": "ok",
                    "version": "8.x.x",    # версия Elasticsearch
                    "url": "https://..."     # URL Elasticsearch
                }

        Выбрасывает:
            WazuhConnectionError: если ES URL не указан, или при ошибке подключения
        """
        if not self.es_url:
            raise WazuhConnectionError("ES URL не указан. Передайте es_url при инициализации.")

        # Создаём отдельную сессию для Elasticsearch с Basic Auth
        es_session = requests.Session()
        es_session.verify = self.es_verify_ssl
        es_session.auth = (self.es_user, self.es_pass)

        try:
            # Проверяем доступность ES, запрашивая корневой endpoint
            resp = es_session.get(
                self.es_url,
                timeout=self.DEFAULT_TIMEOUT,
            )
            resp.raise_for_status()
            info = resp.json()
            # Версия ES находится в поле version.number
            version = info.get("version", {}).get("number", "unknown")
            self.es_session = es_session
            logger.info(f"Connected to Elasticsearch {version} at {self.es_url}")
            return {"status": "ok", "version": version, "url": self.es_url}

        except requests.exceptions.ConnectionError:
            raise WazuhConnectionError(
                f"Не удалось подключиться к Elasticsearch {self.es_url}. "
                f"Проверьте, что ES запущен."
            )
        except requests.exceptions.Timeout:
            raise WazuhConnectionError(f"Таймаут подключения к Elasticsearch {self.es_url}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise WazuhConnectionError("Неверный логин или пароль Elasticsearch")
            raise WazuhConnectionError(f"ES HTTP ошибка: {e.response.status_code}")
        except Exception as e:
            raise WazuhConnectionError(f"Ошибка подключения к Elasticsearch: {str(e)}")

    def _api_get(self, path: str, params: dict = None) -> dict:
        """
        Выполнить GET-запрос к Wazuh Manager API.

        Внутренний метод для всех запросов к Wazuh API. Автоматически
        обрабатывает просроченные JWT-токены: при получении 401 повторно
        вызывает connect() и повторяет запрос.

        Параметры:
            path (str):     Путь API (например "/agents", "/?pretty=true")
            params (dict):  Query-параметры запроса

        Возвращает:
            dict: JSON-ответ Wazuh API

        Выбрасывает:
            WazuhConnectionError: если не подключён к Wazuh
            WazuhAPIError: при ошибке запроса
        """
        if not self.connected:
            raise WazuhConnectionError("Не подключено к Wazuh. Вызовите connect() сначала.")

        url = f"{self.base_url}{path}"
        try:
            resp = self.session.get(url, params=params, timeout=self.DEFAULT_TIMEOUT)

            # Если токен просрочен (401) — переподключаемся и повторяем запрос
            if resp.status_code == 401:
                logger.info("Token expired, reconnecting...")
                self.connect()
                resp = self.session.get(url, params=params, timeout=self.DEFAULT_TIMEOUT)

            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Wazuh API error: GET {path} - {str(e)}")
            raise WazuhAPIError(f"Ошибка запроса к Wazuh API: {str(e)}")

    # ============================================================
    #  Поиск в Elasticsearch
    # ============================================================

    def _es_search(self, query: dict, from_: int = 0, size: int = 100,
                   sort: list = None) -> dict:
        """
        Выполнить поиск в Elasticsearch по индексу wazuh-alerts-4.x-*.

        Это базовый метод для всех поисковых запросов к ES. Отправляет
        POST-запрос к /wazuh-alerts-4.x-*/_search с DSL-запросом.

        Используется всеми методами search_*() и get_alerts().

        Параметры:
            query (dict):  ES DSL query (bool/must/should, term, range, wildcard и т.д.)
            from_ (int):   Смещение результатов (для пагинации, 0-based)
            size (int):    Количество возвращаемых результатов (макс. 10000)
            sort (list):   Список сортировок, например [{"@timestamp": {"order": "desc"}}]

        Возвращает:
            dict: Результаты поиска:
                {
                    "hits": [...],   # список _source документов (алертов)
                    "total": N       # общее количество подходящих документов
                }

        Выбрасывает:
            WazuhConnectionError: если ES сессия не инициализирована
            WazuhAPIError: при ошибке поиска в ES
        """
        if not self.es_session:
            raise WazuhConnectionError(
                "ES сессия не инициализирована. Вызовите connect_es() сначала."
            )

        # Формируем тело запроса Elasticsearch DSL
        es_body = {
            "query": query,                      # DSL-запрос (bool, term, range и т.д.)
            "from": from_,                       # смещение (для пагинации)
            "size": min(size, 10000),            # кол-во результатов (ES макс. 10000)
            "track_total_hits": True,            # точный подсчёт общего кол-ва hits
        }
        if sort:
            es_body["sort"] = sort               # сортировка (обычно по @timestamp desc)

        # URL для поиска по всем индексам wazuh-alerts-4.x-* (шаблон индекса)
        url = f"{self.es_url}/wazuh-alerts-4.x-*/_search"
        try:
            resp = self.es_session.post(
                url,
                json=es_body,
                timeout=self.DEFAULT_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()

            # Извлекаем _source из каждого hit (это сами документы-алерты)
            hits = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
            total = data.get("hits", {}).get("total", {}).get("value", len(hits))

            return {"hits": hits, "total": total}

        except requests.exceptions.RequestException as e:
            logger.error(f"ES search error: {str(e)}")
            raise WazuhAPIError(f"Ошибка поиска в Elasticsearch: {str(e)}")

    # ============================================================
    #  Агенты (через Wazuh API)
    # ============================================================

    def get_agents(self, status: str = "active") -> list[dict]:
        """
        Получить список агентов Wazuh через Wazuh Manager API.

        Агенты — это хосты, на которых установлен Wazuh Agent. Они
        отправляют логи и события на Wazuh Manager для анализа.

        Wazuh API endpoint: GET /agents
        Параметр select: только плоские поля (id, name, ip, status, version,
        lastKeepAlive) — вложенные поля (os, group) вызывают 400 Bad Request.

        Параметры:
            status (str): Фильтр по статусу агента:
                - "active" (по умолчанию) — активные агенты (онлайн)
                - "disconnected" — отключённые (офлайн)
                - "never_connected" — никогда не подключавшиеся
                - "all" — все агенты без фильтра

        Возвращает:
            list[dict]: Список агентов в унифицированном формате:
                [
                    {
                        "id": "001",                          # ID агента в Wazuh
                        "name": "WS-01",                       # имя хоста
                        "ip": "192.168.1.100",                 # IP-адрес агента
                        "status": "active",                    # текущий статус
                        "os": "Windows",                       # название ОС
                        "os_version": "10.0",                  # версия ОС
                        "version": "v4.14.7",                  # версия Wazuh Agent
                        "last_keepalive": "2026-08-03T...",    # последнее время связи
                        "group": "default"                     # группа конфигурации
                    },
                    ...
                ]
        """
        params = {
            "offset": 0,                                      # начиная с первого
            "limit": 500,                                     # макс. 500 агентов
            "status": status,                                 # фильтр по статусу
            "select": "id,name,ip,status,version,lastKeepAlive",  # только нужные поля
        }
        # GET /agents — запрос к Wazuh Manager API
        result = self._api_get("/agents", params=params)

        # Преобразуем ответ Wazuh API в унифицированный формат
        agents = []
        for a in result.get("data", {}).get("affected_items", []):
            agents.append({
                "id": a.get("id"),                                    # ID агента ("001", "002", ...)
                "name": a.get("name"),                                 # имя хоста
                "ip": a.get("ip", "0.0.0.0"),                         # IP-адрес
                "status": a.get("status"),                             # статус (active/disconnected)
                "os": a.get("os", {}).get("name", "unknown") if isinstance(a.get("os"), dict) else "unknown",
                "os_version": a.get("os", {}).get("version", "") if isinstance(a.get("os"), dict) else "",
                "version": a.get("version", ""),                      # версия Wazuh Agent
                "last_keepalive": a.get("lastKeepAlive", ""),         # последнее время связи
                "group": ", ".join(a.get("group", [])) if isinstance(a.get("group"), list) else a.get("group", ""),
            })

        return agents

    # ============================================================
    #  Алерты (через Elasticsearch)
    # ============================================================

    def get_alerts(
        self,
        offset: int = 0,
        limit: int = 100,
        sort: str = "-timestamp",
        q: str = "",
        search: str = "",
        rule_ids: list[str] = None,
        agents: list[str] = None,
        from_time: str = "",
        to_time: str = "",
        severity_min: int = 0,
        exclude_sca: bool = True,
    ) -> dict:
        """
        Поиск алертов в Elasticsearch (индекс wazuh-alerts-4.x-*).

        Универсальный метод для получения алертов с гибкой фильтрацией.
        Используется эндпоинтом /api/wazuh/alerts в app.py для отображения
        списка алертов в UI.

        ES-запрос строится динамически из параметров:
        ──────────────────────────────────────────
        agents      → term/terms filter на agent.id
        from_time   → range filter на @timestamp (>=)
        to_time     → range filter на @timestamp (<=)
        severity_min → range filter на rule.level (>=)
        rule_ids    → terms filter на rule.id
        search      → wildcard query на full_log.keyword
        q           → парсинг Wazuh query string в ES bool query
        exclude_sca → must_not wildcard на rule.groups=*sca*

        Параметры:
            offset (int):       Смещение результатов (для пагинации)
            limit (int):        Количество результатов (макс. 10000)
            sort (str):         Сортировка: "-timestamp" (DESC) или "timestamp" (ASC)
            q (str):            Wazuh query string (парсится в ES bool query)
                                Примеры: "rule.level>5", "agent.id=001 AND rule.level>3"
            search (str):       Полнотекстовый поиск по full_log (wildcard)
            rule_ids (list):    Фильтр по ID правил Wazuh (например ["5716", "5503"])
            agents (list):      Фильтр по ID агентов (например ["001", "002"])
            from_time (str):    Начало временного окна (ISO 8601, например "2026-08-03T00:00:00.000Z")
            to_time (str):      Конец временного окна (ISO 8601)
            severity_min (int): Минимальный уровень серьёзности (0-15)
            exclude_sca (bool): Исключить SCA/CIS compliance алерты (по умолчанию True)

        Возвращает:
            dict: {"alerts": [...], "total": 123}
                alerts — список документов-алертов из ES (_source)
                total  — общее количество подходящих документов
        """
        must = []  # Условия, которые ДОЛЖНЫ выполняться (AND)

        # agents → term/terms filter на agent.id
        # term — для одного агента (оптимизация), terms — для нескольких
        if agents:
            if len(agents) == 1:
                must.append({"term": {"agent.id": agents[0]}})
            else:
                must.append({"terms": {"agent.id": agents}})

        # from_time / to_time → range filter на @timestamp
        # Ограничиваем временное окно поиска
        time_range = {}
        if from_time:
            time_range["gte"] = from_time  # greater than or equal
        if to_time:
            time_range["lte"] = to_time    # less than or equal
        if time_range:
            must.append({"range": {"@timestamp": time_range}})

        # severity_min → range filter на rule.level
        # Wazuh severity: 0-2 (info), 3-6 (warning), 7-10 (error), 11-15 (critical)
        if severity_min > 0:
            must.append({"range": {"rule.level": {"gte": severity_min}}})

        # rule_ids → terms filter на rule.id
        # Фильтрация по конкретным правилам Wazuh
        if rule_ids:
            must.append({"terms": {"rule.id": rule_ids}})

        # search → wildcard query на full_log.keyword
        # Полнотекстовый поиск по полному логу события
        if search:
            must.append({"wildcard": {"full_log.keyword": f"*{search}*"}})

        # q → парсинг Wazuh query string в ES bool query
        # Поддерживает: =, !=, >, >=, <, <=, ~, ~=, |, AND
        if q:
            q_query = self._parse_q_to_es(q)
            if q_query:
                must.append(q_query)

        # Формируем итоговый ES-запрос
        must_not = []  # Условия, которые НЕ должны выполняться (NOT)

        # exclude_sca — убираем SCA (Security Configuration Assessment) алерты
        # SCA-алерты — это проверки соответствия CIS benchmarks, не связанные с атаками
        if exclude_sca:
            must_not.append({"wildcard": {"rule.groups": "*sca*"}})

        # Собираем bool query
        if must or must_not:
            bool_query = {}
            if must:
                bool_query["must"] = must        # условия AND
            if must_not:
                bool_query["must_not"] = must_not  # условия NOT
            query = {"bool": bool_query}
        else:
            query = {"match_all": {}}  # без фильтров — вернуть все документы

        # Сортировка: по умолчанию — новые первыми (@timestamp DESC)
        es_sort = []
        if sort == "-timestamp":
            es_sort = [{"@timestamp": {"order": "desc"}}]
        elif sort == "timestamp":
            es_sort = [{"@timestamp": {"order": "asc"}}]

        # Выполняем поиск в Elasticsearch
        result = self._es_search(query, from_=offset, size=limit, sort=es_sort)
        return {"alerts": result["hits"], "total": result["total"]}

    def get_alert_by_id(self, alert_id: str) -> Optional[dict]:
        """
        Получить конкретный алерт по его ID через Elasticsearch.

        Использует term query по полю "id" для точного поиска.
        Возвращает первый найденный документ или None.

        Параметры:
            alert_id (str): ID алерта в Wazuh/ES

        Возвращает:
            dict|None: Документ алерта (_source) или None, если не найден
        """
        query = {"term": {"id": alert_id}}
        result = self._es_search(query, size=1)
        if result["hits"]:
            return result["hits"][0]
        return None

    # ============================================================
    #  Методы для построения графа цепочки атаки (через ES)
    #  Каждый метод соответствует одному шагу 6-шагового алгоритма
    # ============================================================

    def search_auth_events(
        self, agent_id: str, user_name: str = "", time_window_min: int = 60
    ) -> list[dict]:
        """
        Запрос 1: Поиск событий аутентификации на агенте.

        Ищет алерты, связанные с входом/выходом пользователей на хосте.
        Это первый шаг алгоритма — позволяет определить, кто входил
        на скомпрометированный хост и откуда.

        ES-запрос:
        ──────────
        must:
          - term: agent.id = {agent_id}           (алерты конкретного агента)
          - range: @timestamp >= {from_time}       (временное окно)
          - bool.should:                           (тип события = аутентификация)
              - wildcard: rule.groups = *authentication*
              - terms: rule.id = [5503, 5502, 5103, 5104]
          - bool.should (опционально):             (фильтр по пользователю)
              - term: data.auth.user = {user_name}
              - term: data.srcuser = {user_name}

        Wazuh-поля:
            data.auth.user  — пользователь аутентификации (Linux)
            data.srcuser    — исходный пользователь (sudo)
            rule.groups     — группа "authentication"
            rule.id 5503    — успешный вход (SSH)
            rule.id 5502    — неуспешный вход (SSH)
            rule.id 5103    — успешный вход (Windows)
            rule.id 5104    — неуспешный вход (Windows)

        Параметры:
            agent_id (str):         ID агента Wazuh (например "001")
            user_name (str):        Имя пользователя для фильтрации (опционально)
            time_window_min (int):  Временное окно в минутах (по умолчанию 60)

        Возвращает:
            list[dict]: Список документов-алертов из ES (макс. 50)
        """
        from_time = self._time_ago(time_window_min)
        must = [
            {"term": {"agent.id": agent_id}},               # алерты конкретного агента
            {"range": {"@timestamp": {"gte": from_time}}},  # временное окно
        ]

        # Фильтр по имени пользователя (если указан)
        # Ищем в двух полях: data.auth.user (Linux) и data.srcuser (sudo)
        if user_name:
            must.append({
                "bool": {
                    "should": [
                        {"term": {"data.auth.user": user_name}},   # пользователь аутентификации
                        {"term": {"data.srcuser": user_name}},     # исходный пользователь (sudo)
                    ],
                    "minimum_should_match": 1,  # хотя бы одно из условий
                }
            })

        # Фильтр по типу события: аутентификация
        # Ищем по группе правил "authentication" или конкретным rule IDs
        must.append({
            "bool": {
                "should": [
                    {"wildcard": {"rule.groups": "*authentication*"}},  # группа authentication
                    {"terms": {"rule.id": ["5503", "5502", "5103", "5104"]}},  # конкретные rule IDs
                ],
                "minimum_should_match": 1,
            }
        })

        query = {"bool": {"must": must}}
        result = self._es_search(query, size=50)
        return result["hits"]

    def search_network_connections(
        self, agent_id: str, time_window_min: int = 60
    ) -> list[dict]:
        """
        Запрос 2: Поиск сетевых соединений с агента.

        Ищет алерты, связанные с сетевой активностью хоста: firewall events,
        network connections, DNS queries. Помогает обнаружить C2-соединения,
        exfiltration и lateral movement.

        ES-запрос:
        ──────────
        must:
          - term: agent.id = {agent_id}
          - range: @timestamp >= {from_time}
          - bool.should:
              - wildcard: rule.groups = *firewall*
              - wildcard: rule.groups = *network*
              - terms: rule.id = [5102, 5105, 5106]

        Wazuh-поля:
            srcip, dstip    — IP-источник и назначение
            srcport, dstport — порты
            rule.groups     — "firewall", "network", "dns"
            rule.id 5102    — исходящее соединение
            rule.id 5105    — входящее соединение
            rule.id 5106    — DNS-запрос

        Параметры:
            agent_id (str):         ID агента Wazuh
            time_window_min (int):  Временное окно в минутах (по умолчанию 60)

        Возвращает:
            list[dict]: Список документов-алертов из ES (макс. 100)
        """
        from_time = self._time_ago(time_window_min)
        query = {
            "bool": {
                "must": [
                    {"term": {"agent.id": agent_id}},               # конкретный агент
                    {"range": {"@timestamp": {"gte": from_time}}},  # временное окно
                    {
                        "bool": {
                            "should": [
                                {"wildcard": {"rule.groups": "*firewall*"}},   # firewall events
                                {"wildcard": {"rule.groups": "*network*"}},    # network events
                                {"terms": {"rule.id": ["5102", "5105", "5106"]}},  # конкретные rule IDs
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        }
        result = self._es_search(query, size=100)
        return result["hits"]

    def search_related_alerts(
        self, agent_id: str, severity_min: int = 5, time_window_min: int = 60
    ) -> list[dict]:
        """
        Запрос 3: Поиск других алертов на том же хосте (severity > N).

        Ищет все алерты с высоким уровнем серьёзности на том же агенте.
        Помогает обнаружить escalation, persistence и другие аномалии,
        которые могут быть частью той же атаки.

        ES-запрос:
        ──────────
        must:
          - term: agent.id = {agent_id}
          - range: @timestamp >= {from_time}
          - range: rule.level > {severity_min}

        Параметры:
            agent_id (str):         ID агента Wazuh
            severity_min (int):     Минимальный уровень серьёзности (по умолчанию 5)
            time_window_min (int):  Временное окно в минутах (по умолчанию 60)

        Возвращает:
            list[dict]: Список документов-алертов из ES (макс. 100)
        """
        from_time = self._time_ago(time_window_min)
        query = {
            "bool": {
                "must": [
                    {"term": {"agent.id": agent_id}},               # конкретный агент
                    {"range": {"@timestamp": {"gte": from_time}}},  # временное окно
                    {"range": {"rule.level": {"gt": severity_min}}},  # severity > N
                ]
            }
        }
        result = self._es_search(query, size=100)
        return result["hits"]

    def search_ip_on_other_hosts(
        self, src_ip: str, exclude_agent_id: str, time_window_min: int = 60
    ) -> list[dict]:
        """
        Запрос 4: Поиск событий с тем же IP на других хостах (латеральное движение).

        Ключевой индикатор lateral movement: один и тот же IP-атакующий
        появляется на разных машинах. Например, если IP 192.168.1.105
        замечен на WS-01, а затем на WS-02 — атакующий перемещается
        по сети.

        ES-запрос:
        ──────────
        must:
          - term: srcip = {src_ip}                 (IP-источник атаки)
          - range: @timestamp >= {from_time}
        must_not:
          - term: agent.id = {exclude_agent_id}    (исключить текущий хост)

        Wazuh-поля:
            srcip    — IP-источник (верхний уровень или data.srcip)
            agent.id — ID агента, на котором замечен IP

        Параметры:
            src_ip (str):            IP-источник атаки для поиска
            exclude_agent_id (str):  ID агента, который нужно исключить (текущий хост)
            time_window_min (int):   Временное окно в минутах (по умолчанию 60)

        Возвращает:
            list[dict]: Список алертов с этим IP на других хостах (макс. 100)
        """
        from_time = self._time_ago(time_window_min)
        query = {
            "bool": {
                "must": [
                    {"term": {"srcip": src_ip}},                    # IP-источник = искомый
                    {"range": {"@timestamp": {"gte": from_time}}},  # временное окно
                ],
                "must_not": [
                    {"term": {"agent.id": exclude_agent_id}},       # исключить текущий агент
                ]
            }
        }
        result = self._es_search(query, size=100)
        return result["hits"]

    def search_process_events(
        self, agent_id: str, process_name: str = "", time_window_min: int = 60
    ) -> list[dict]:
        """
        Запрос 5: Поиск событий, связанных с процессом.

        Ищет все алерты, в полном логе которых упоминается указанный процесс.
        Помогает обнаружить цепочку выполнения: родительские и дочерние
        процессы, повторные запуски, аргументы командной строки.

        ES-запрос:
        ──────────
        must:
          - term: agent.id = {agent_id}
          - range: @timestamp >= {from_time}
          - wildcard: full_log.keyword = *{process_name}* (опционально)

        Wazuh-поля:
            full_log — полный текст лога (поиск по подстроке)

        Параметры:
            agent_id (str):         ID агента Wazuh
            process_name (str):     Имя процесса для поиска в full_log (опционально)
            time_window_min (int):  Временное окно в минутах (по умолчанию 60)

        Возвращает:
            list[dict]: Список документов-алертов из ES (макс. 50)
        """
        from_time = self._time_ago(time_window_min)
        must = [
            {"term": {"agent.id": agent_id}},               # конкретный агент
            {"range": {"@timestamp": {"gte": from_time}}},  # временное окно
        ]
        # Добавляем wildcard-поиск по full_log, если указано имя процесса
        # full_log.keyword — keyword-поле для точного wildcard (без анализа)
        if process_name:
            must.append({"wildcard": {"full_log.keyword": f"*{process_name}*"}})

        query = {"bool": {"must": must}}
        result = self._es_search(query, size=50)
        return result["hits"]

    def search_file_events(
        self, agent_id: str, time_window_min: int = 60
    ) -> list[dict]:
        """
        Запрос 6: Подозрительные файловые операции на агенте.

        Ищет алерты syscheck (File Integrity Monitoring) — изменения файлов
        на хосте. Помогает обнаружить:
        - Malware droppers (создание .exe, .dll в нестандартных папках)
        - Persistence mechanisms (изменение автозагрузки, Task Scheduler)
        - Data theft (чтение конфиденциальных файлов)
        - Ransomware (массовое изменение файлов)

        ES-запрос:
        ──────────
        must:
          - term: agent.id = {agent_id}
          - range: @timestamp >= {from_time}
          - bool.should:
              - wildcard: rule.groups = *syscheck*
              - terms: rule.id = [554, 550, 553]

        Wazuh-поля:
            data.syscheck.path   — путь к изменённому файлу
            data.syscheck.event  — тип изменения (added/modified/deleted)
            rule.groups          — "syscheck"
            rule.id 554          — файл добавлен
            rule.id 550          — файл изменён
            rule.id 553          — файл удалён

        Параметры:
            agent_id (str):         ID агента Wazuh
            time_window_min (int):  Временное окно в минутах (по умолчанию 60)

        Возвращает:
            list[dict]: Список алертов файловых операций (макс. 50)
        """
        from_time = self._time_ago(time_window_min)
        query = {
            "bool": {
                "must": [
                    {"term": {"agent.id": agent_id}},               # конкретный агент
                    {"range": {"@timestamp": {"gte": from_time}}},  # временное окно
                    {
                        "bool": {
                            "should": [
                                {"wildcard": {"rule.groups": "*syscheck*"}},   # syscheck/FIM events
                                {"terms": {"rule.id": ["554", "550", "553"]}},  # добавлен/изменён/удалён
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        }
        result = self._es_search(query, size=50)
        return result["hits"]

    # ============================================================
    #  Парсер Wazuh query string → ES bool query
    #  Преобразует синтаксис Wazuh (field=val, field>5, |, AND)
    #  в Elasticsearch DSL bool query
    # ============================================================

    def _parse_q_to_es(self, q: str) -> Optional[dict]:
        """
        Преобразовать Wazuh query string в Elasticsearch bool query.

        Wazuh query string — это упрощённый синтаксис для фильтрации:
          agent.id=001              → term query
          rule.level>5             → range query
          agent.id=001|agent.id=002 → OR (should)
          agent.id=001 AND rule.level>5 → AND (must)

        Параметры:
            q (str): Wazuh query string

        Возвращает:
            dict|None: ES DSL query или None, если строка пустая
        """
        q = q.strip()
        if not q:
            return None
        return self._parse_q_expr(q)

    def _parse_q_expr(self, q: str) -> dict:
        """
        Разобрать выражение с OR (|) и AND на верхнем уровне.

        Рекурсивный парсер: сначала разбивает по | (OR), затем
        по AND, затем парсит атомарное выражение (field op value).

        Порядок старшинства: OR (|) < AND < атом (field op value)

        Параметры:
            q (str): Строка выражения

        Возвращает:
            dict: ES DSL bool query
        """
        q = q.strip()
        # Убираем внешние скобки, если они парные: "(A | B)" → "A | B"
        if q.startswith('(') and q.endswith(')') and self._is_matching_parens(q):
            q = q[1:-1].strip()

        # Разбиваем по | на верхнем уровне (OR)
        # Учитываем скобки: "A | (B | C)" → ["A", "(B | C)"]
        or_parts = self._split_top_level(q, '|')
        if len(or_parts) > 1:
            should = [self._parse_q_and(p.strip()) for p in or_parts if p.strip()]
            return {"bool": {"should": should, "minimum_should_match": 1}}

        return self._parse_q_and(q)

    def _parse_q_and(self, q: str) -> dict:
        """
        Разобрать AND-выражение на верхнем уровне.

        Разбивает строку по ' AND ' (с пробелами) и объединяет
        части через bool.must (логическое И).

        Параметры:
            q (str): Строка AND-выражения

        Возвращает:
            dict: ES DSL bool query
        """
        q = q.strip()
        # Убираем внешние парные скобки
        if q.startswith('(') and q.endswith(')') and self._is_matching_parens(q):
            q = q[1:-1].strip()

        # Разбиваем по ' AND ' на верхнем уровне
        and_parts = self._split_top_level(q, ' AND ')
        if len(and_parts) > 1:
            must = [self._parse_q_expr(p.strip()) for p in and_parts if p.strip()]
            return {"bool": {"must": must}}

        return self._parse_q_atom(q)

    def _parse_q_atom(self, expr: str) -> dict:
        """
        Разобрать атомарное выражение (field operator value).

        Поддерживаемые операторы (в порядке проверки — сначала составные):
          !=  → bool.must_not + term        (field!=value → NOT field=value)
          >=  → range gte                   (field>=5 → field >= 5)
          <=  → range lte                   (field<=10 → field <= 10)
          ~=  → wildcard                    (field~=val → *val*)
          ~   → wildcard                    (field~val → *val*)
          >   → range gt                    (field>5 → field > 5)
          <   → range lt                    (field<10 → field < 10)
          =   → term                        (field=value → exact match)

        Если ни один оператор не найден, возвращает match_all.

        Параметры:
            expr (str): Атомарное выражение (например "rule.level>5")

        Возвращает:
            dict: ES DSL query (term, range, wildcard, bool.must_not или match_all)
        """
        expr = expr.strip()
        # Убираем внешние скобки
        if expr.startswith('(') and expr.endswith(')') and self._is_matching_parens(expr):
            inner = expr[1:-1].strip()
            # Если внутри есть | на верхнем уровне, это OR-выражение
            if self._has_top_level_char(inner, '|'):
                return self._parse_q_expr(inner)
            expr = inner

        # Проверяем операторы (порядок важен: сначала составные !=, >=, <=, ~=)
        if '!=' in expr:
            # != — отрицание: field!=value → must_not + term
            field, value = expr.split('!=', 1)
            return {"bool": {"must_not": [{"term": {field.strip(): value.strip()}}]}}
        elif '>=' in expr:
            # >= — больше или равно: field>=5 → range gte
            field, value = expr.split('>=', 1)
            return {"range": {field.strip(): {"gte": self._coerce_num(value.strip())}}}
        elif '<=' in expr:
            # <= — меньше или равно: field<=10 → range lte
            field, value = expr.split('<=', 1)
            return {"range": {field.strip(): {"lte": self._coerce_num(value.strip())}}}
        elif '~=' in expr:
            # ~= — wildcard-совпадение: field~=val → *val*
            parts = expr.split('~=', 1)
            field, value = parts[0].strip(), parts[1].strip()
            return {"wildcard": {field: f"*{value}*"}}
        elif '~' in expr:
            # ~ — wildcard-совпадение (без =): field~val → *val*
            parts = expr.split('~', 1)
            field, value = parts[0].strip(), parts[1].strip()
            return {"wildcard": {field: f"*{value}*"}}
        elif '>' in expr:
            # > — строго больше: field>5 → range gt
            field, value = expr.split('>', 1)
            return {"range": {field.strip(): {"gt": self._coerce_num(value.strip())}}}
        elif '<' in expr:
            # < — строго меньше: field<10 → range lt
            field, value = expr.split('<', 1)
            return {"range": {field.strip(): {"lt": self._coerce_num(value.strip())}}}
        elif '=' in expr:
            # = — точное совпадение: field=value → term query
            field, value = expr.split('=', 1)
            return {"term": {field.strip(): value.strip()}}
        else:
            # Нет оператора — вернуть все документы
            return {"match_all": {}}

    @staticmethod
    def _coerce_num(value: str):
        """
        Попробовать преобразовать строку в число (int или float).

        Используется парсером query string для операторов сравнения
        (>, >=, <, <=), чтобы ES использовал числовое сравнение
        вместо строкового.

        Параметры:
            value (str): Строка для преобразования

        Возвращает:
            int|float|str: Числовое значение или исходная строка
        """
        try:
            return int(value)
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return value  # не число — возвращаем как строку

    @staticmethod
    def _is_matching_parens(s: str) -> bool:
        """
        Проверить, что первая '(' и последняя ')' являются парой.

        Используется парсером для определения, нужно ли убирать
        внешние скобки: "(A | B)" → да, "(A) | (B)" → нет.

        Алгоритм: считаем глубину вложенности скобок. Если глубина
        становится 0 до конца строки — первая и последняя скобки
        не являются парой.

        Параметры:
            s (str): Строка для проверки

        Возвращает:
            bool: True, если внешние скобки — пара
        """
        if not s.startswith('(') or not s.endswith(')'):
            return False
        depth = 0
        for i, c in enumerate(s):
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            # Если глубина 0 до конца строки — скобки не парные
            if depth == 0 and i < len(s) - 1:
                return False
        return depth == 0

    @staticmethod
    def _split_top_level(s: str, delimiter: str) -> list:
        """
        Разбить строку по разделителю, игнорируя содержимое в скобках.

        Парсер использует этот метод для разбиения выражений по | и AND,
        не затрагивая подвыражения в скобках.

        Примеры:
            _split_top_level("A | (B | C)", "|") → ["A ", " (B | C)"]
            _split_top_level("A AND B AND C", " AND ") → ["A", "B", "C"]

        Параметры:
            s (str):          Строка для разбиения
            delimiter (str):  Разделитель (например "|" или " AND ")

        Возвращает:
            list: Список частей строки
        """
        parts = []
        depth = 0       # глубина вложенности скобок
        current = []     # текущая накапливаемая часть
        i = 0
        dlen = len(delimiter)
        while i < len(s):
            if s[i] == '(':
                depth += 1
                current.append(s[i])
            elif s[i] == ')':
                depth -= 1
                current.append(s[i])
            elif depth == 0 and s[i:i + dlen] == delimiter:
                # Разделитель найден на верхнем уровне (вне скобок)
                parts.append(''.join(current))
                current = []
                i += dlen
                continue
            else:
                current.append(s[i])
            i += 1
        parts.append(''.join(current))  # добавляем последнюю часть
        return parts

    @staticmethod
    def _has_top_level_char(s: str, char: str) -> bool:
        """
        Проверить, есть ли символ на верхнем уровне (вне скобок).

        Используется парсером для определения, содержит ли выражение
        оператор OR (|) после удаления внешних скобок.

        Параметры:
            s (str):    Строка для проверки
            char (str): Искомый символ (обычно "|")

        Возвращает:
            bool: True, если символ найден на верхнем уровне
        """
        depth = 0
        for c in s:
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            elif depth == 0 and c == char:
                return True
        return False

    # ============================================================
    #  Вспомогательные методы
    # ============================================================

    @staticmethod
    def _time_ago(minutes: int) -> str:
        """
        Вернуть ISO-8601 строку времени 'N минут назад' от текущего момента.

        Используется для формирования параметра from_time в ES-запросах
        (range filter на @timestamp).

        Параметры:
            minutes (int): Количество минут назад (0 = текущее время)

        Возвращает:
            str: ISO-8601 строка в формате "2026-08-03T12:00:00.000Z"
        """
        t = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def get_alert_detail_for_graph(self, alert: dict) -> dict:
        """
        Извлечь релевантные поля из алерта Wazuh в унифицированный формат
        для графового движка (GraphEngine._extract_from_alert).

        Wazuh хранит данные в глубоко вложенной структуре, которая зависит
        от типа алерта (Linux/Windows/syscheck). Этот метод нормализует
        различные варианты расположения полей в единый плоский словарь.

        Соответствие полей Wazuh → унифицированный формат:
        ─────────────────────────────────────────────────
        Wazuh поле                              → Выходное поле
        ────────────────────────────────────────
        data.auth.user                          → user_name (Linux auth)
        data.audit.login.user                   → user_name (Linux audit)
        data.srcuser                            → user_name (sudo)
        data.win.eventdata.targetUserName       → user_name (Windows)
        data.win.eventdata.image                → process_name (Windows)
        data.process.name                       → process_name (Linux)
        data.win.eventdata.commandLine          → process_cmd (Windows)
        data.process.cmd                        → process_cmd (Linux)
        data.win.eventdata.targetFilename       → file_path (Windows)
        data.syscheck.path                      → file_path (syscheck)
        data.win.eventdata.actionType           → file_action (Windows)
        data.syscheck.event                     → file_action (syscheck)
        data.srcip / srcip                      → src_ip
        data.dstip / dstip                      → dst_ip
        rule.id                                 → rule_id
        rule.description                        → rule_description
        rule.level                              → severity
        rule.groups                             → rule_groups
        agent.id                                → agent_id
        agent.name                              → agent_name
        agent.ip                                → agent_ip

        Параметры:
            alert (dict): Исходный документ алерта из Elasticsearch (_source)

        Возвращает:
            dict: Унифицированный алерт с плоской структурой:
                {
                    "event_id": "...",           # ID события в Wazuh
                    "timestamp": "2026-...",     # время события
                    "rule_id": "5716",           # ID правила
                    "rule_description": "...",   # описание правила
                    "severity": 7,               # уровень серьёзности (0-15)
                    "rule_groups": [...],        # группы правил
                    "agent_id": "001",           # ID агента
                    "agent_name": "WS-01",       # имя агента
                    "agent_ip": "192.168.1.100", # IP агента
                    "src_ip": "192.168.1.105",   # IP-источник
                    "dst_ip": "10.0.0.1",        # IP-назначение
                    "src_port": 12345,           # порт источника
                    "dst_port": 80,              # порт назначения
                    "user_name": "admin",        # пользователь
                    "process_name": "ps.exe",    # процесс
                    "process_cmd": "...",        # командная строка
                    "file_path": "C:\\...",      # путь к файлу
                    "file_action": "modified",   # действие с файлом
                    "category": "process",       # категория (auth/network/process/registry/file)
                    "full_log": "..."            # полный лог
                }
        """
        # Извлекаем основные секции алерта
        data = alert.get("data", {}) or {}    # секция data (основная нагрузка)
        rule = alert.get("rule", {}) or {}    # секция rule (метаданные правила)
        agent = alert.get("agent", {}) or {}  # секция agent (информация об агенте)

        # Вспомогательная функция для безопасного извлечения вложенных полей
        # safe_get(data, "win", "eventdata", "image") → data.win.eventdata.image
        def safe_get(d: dict, *keys, default=None):
            """
            Безопасно извлечь вложенное значение из словаря.

            Проходит по цепочке ключей, возвращая default, если любой
            промежуточный ключ отсутствует или значение не является dict.
            """
            current = d
            for k in keys:
                if isinstance(current, dict):
                    current = current.get(k, {})
                else:
                    return default
            return current if current != {} else default

        # --- Извлечение имени пользователя ---
        # Порядок: Linux auth → Linux audit → sudo → Windows
        user_name = (
            safe_get(data, "auth", "user")                        # Linux: SSH/su вход
            or safe_get(data, "audit", "login", "user")           # Linux: audit login
            or safe_get(data, "srcuser")                          # Linux: sudo source user
            or safe_get(alert, "data", "win", "eventdata", "targetUserName")  # Windows: logon
            or ""
        )

        # --- Извлечение имени процесса ---
        # Порядок: Windows image → Linux process name
        process_name = (
            safe_get(data, "win", "eventdata", "image")           # Windows: полный путь к exe
            or safe_get(data, "process", "name")                  # Linux: имя процесса
            or ""
        )

        # --- Извлечение командной строки процесса ---
        # Порядок: Windows commandLine → Linux process cmd
        process_cmd = (
            safe_get(data, "win", "eventdata", "commandLine")     # Windows: командная строка
            or safe_get(data, "process", "cmd")                   # Linux: аргументы процесса
            or ""
        )

        # --- Извлечение пути к файлу ---
        # Порядок: Windows targetFilename → syscheck path
        file_path = (
            safe_get(data, "win", "eventdata", "targetFilename")  # Windows: путь к файлу
            or safe_get(data, "syscheck", "path")                 # syscheck/FIM: мониторинг файлов
            or ""
        )

        # --- Извлечение действия с файлом ---
        # Порядок: Windows actionType → syscheck event
        file_action = (
            safe_get(data, "win", "eventdata", "actionType")      # Windows: тип действия
            or safe_get(data, "syscheck", "event")                # syscheck: added/modified/deleted
            or ""
        )

        # Формируем унифицированный словарь
        return {
            "event_id": alert.get("id", ""),                      # ID события Wazuh
            "timestamp": alert.get("timestamp", ""),              # время события
            "rule_id": str(rule.get("id", "")),                   # ID правила (строка)
            "rule_description": rule.get("description", ""),      # описание правила
            "severity": rule.get("level", 0),                     # уровень серьёзности
            "rule_groups": rule.get("groups", []),                # группы правил
            "agent_id": agent.get("id", ""),                      # ID агента
            "agent_name": agent.get("name", ""),                  # имя агента
            "agent_ip": agent.get("ip", ""),                      # IP агента
            "src_ip": data.get("srcip") or alert.get("srcip", ""),  # IP-источник (data.srcip или srcip)
            "dst_ip": data.get("dstip") or alert.get("dstip", ""),  # IP-назначение
            "src_port": data.get("srcport"),                      # порт источника
            "dst_port": data.get("dstport"),                      # порт назначения
            "user_name": user_name,                               # пользователь
            "process_name": process_name,                         # процесс
            "process_cmd": process_cmd,                           # командная строка
            "file_path": file_path,                               # путь к файлу
            "file_action": file_action,                           # действие с файлом
            "category": self._detect_category(alert),             # категория алерта
            "full_log": alert.get("full_log", ""),                # полный лог
        }

    @staticmethod
    def _detect_category(alert: dict) -> str:
        """
        Определить категорию алерта Wazuh для классификации в графе.

        Категория определяет, какие узлы и рёбра будут созданы
        в GraphEngine._extract_from_alert(). Логика определения:

        1. authentication — rule.groups содержит "authentication"
           или rule.id ∈ {5503, 5502, 5103, 5104}
           (вход/выход, SSH, Windows logon)

        2. network — rule.groups содержит "firewall", "network" или "dns"
           или rule.id ∈ {5102, 5105, 5106}
           (сетевые соединения, DNS-запросы)

        3. file — rule.groups содержит "syscheck"
           или rule.id ∈ {554, 550, 553}
           (изменения файлов через FIM)

        4. registry — full_log содержит "reg ", "registry", "HKLM" или "HKCU"
           (изменение реестра Windows)

        5. process — по умолчанию для всех остальных алертов
           (запуск процессов, команды и т.д.)

        Параметры:
            alert (dict): Документ алерта из ES

        Возвращает:
            str: Категория алерта: "authentication", "network", "file",
                 "registry" или "process"
        """
        rule_groups = alert.get("rule", {}).get("groups", [])
        groups_str = " ".join(rule_groups)
        rule_id = str(alert.get("rule", {}).get("id", ""))
        full_log = alert.get("full_log", "")

        # 1. Аутентификация — вход/выход пользователей
        if "authentication" in groups_str or rule_id in ("5503", "5502", "5103", "5104"):
            return "authentication"

        # 2. Сетевые события — firewall, network, DNS
        if any(g in groups_str for g in ("firewall", "network", "dns")) or rule_id in ("5102", "5105", "5106"):
            return "network"

        # 3. Файловые события — syscheck (FIM)
        if "syscheck" in groups_str or rule_id in ("554", "550", "553"):
            return "file"

        # 4. Реестр Windows — определяем по содержимому full_log
        # "reg " — команда reg.exe, "registry" — общее упоминание,
        # "HKLM"/"HKCU" — стандартные ульи реестра Windows
        if any(k in full_log for k in ("reg ", "registry", "HKLM", "HKCU")):
            return "registry"

        # 5. По умолчанию — процесс (запуск, выполнение команд)
        return "process"

    def disconnect(self):
        """
        Отключиться от Wazuh API и Elasticsearch.

        Очищает JWT-токен, удаляет Bearer-заголовок из HTTP-сессии
        и сбрасывает сессию Elasticsearch. После вызова этого метода
        клиент нужно повторно подключить через connect() + connect_es().
        """
        self.token = None               # очищаем JWT-токен
        self._connected = False         # сбрасываем флаг подключения
        if "Authorization" in self.session.headers:
            del self.session.headers["Authorization"]  # удаляем Bearer-заголовок
        self.es_session = None          # сбрасываем сессию Elasticsearch
