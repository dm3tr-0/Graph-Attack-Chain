# Graph Attack Chain — Графовый инструмент визуализации цепочек атак

> Дипломная работа: «Разработка графового инструмента визуализации цепочек атак в информационной безопасности»

---

## Оглавление

1. [Общее описание](#1-общее-описание)
2. [Архитектура](#2-архитектура)
3. [Технологический стек](#3-технологический-стек)
4. [Структура проекта](#4-структура-проекта)
5. [Установка и запуск](#5-установка-и-запуск)
6. [Модули и функции — подробное описание](#6-модули-и-функции--подробное-описание)
   - 6.1 [Flask Backend (app.py)](#61-flask-backend-apppy)
   - 6.2 [Клиент Wazuh (wazuh_client.py)](#62-клиент-wazuh-wazuh_clientpy)
   - 6.3 [Графовый движок (graph_engine.py)](#63-графовый-движок-graph_enginepy)
   - 6.4 [Симуляция атак (simulate_attack.py)](#64-симуляция-атак-simulate_attackpy)
   - 6.5 [Фронтенд (page.tsx)](#65-фронтенд-pagetsx)
   - 6.6 [API-прокси (Next.js routes)](#66-api-прокси-nextjs-routes)
7. [Интеграция с Wazuh API — используемые эндпоинты](#7-интеграция-с-wazuh-api--используемые-эндпоинты)
8. [Запросы к Elasticsearch — структура и поля](#8-запросы-к-elasticsearch--структура-и-поля)
9. [Алгоритм построения графа (6 шагов)](#9-алгоритм-построения-графа-6-шагов)
10. [Структура данных графа](#10-структура-данных-графа)
11. [Тестовые сценарии атак](#11-тестовые-сценарии-атак)
12. [Соответствие требованиям дипломной работы](#12-соответствие-требованиям-дипломной-работы)
13. [Ограничения и направления развития](#13-ограничения-и-направления-развития)

---

## 1. Общее описание

**Graph Attack Chain** — инструмент визуализации цепочек атак для SOC-аналитиков, интегрированный с Wazuh SIEM. Инструмент решает проблему фрагментации информации: аналитик видит отдельные алерты от SIEM, но не может быстро восстановить целостную картину атаки.

### Принцип работы

1. Аналитик подключается к Wazuh Manager API и Elasticsearch
2. Выбирает агента и загружает алерты
3. Кликает на конкретный алерт — инструмент автоматически выполняет 6 запросов к Elasticsearch для поиска связанных событий
4. Строится граф атаки: узлы — сущности (IP, хосты, пользователи, процессы, файлы, домены), рёбра — события (аутентификация, запуск процесса, сетевое соединение, файловая операция, DNS-запрос, изменение реестра)
5. Аналитик видит всю цепочку атаки целиком

---

## 2. Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                    Браузер (пользователь)                   │
│  ┌──────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │ Левая панель │  │  Центр — граф    │  │ Правая панель │  │
│  │ Агенты +     │  │  Cytoscape.js    │  │ Детали алерта │  │
│  │ Алерты       │  │  (визуализация)  │  │ + Журнал      │  │
│  └──────────────┘  └──────────────────┘  └───────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP (порт 3000)
┌────────────────────────▼────────────────────────────────────┐
│              Next.js 16 (App Router, порт 3000)             │
│  /api/wazuh/connect → прокси → Flask:5001                   │
│  /api/wazuh/agents  → прокси → Flask:5001                   │
│  /api/wazuh/alerts  → прокси → Flask:5001                   │
│  /api/analyze       → прокси → Flask:5001                   │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP (порт 5001)
┌────────────────────────▼───────────────────────────────────┐
│              Flask Backend (порт 5001)                     │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐ │
│  │ wazuh_client │  │ graph_engine  │  │   app.py         │ │
│  │ (API + ES)   │  │ (6 запросов)  │  │ (маршруты)       │ │
│  └──────┬───────┘  └───────────────┘  └──────────────────┘ │
└─────────┬──────────────────┬───────────────────────────────┘
          │                  │
    ┌─────▼─────┐      ┌─────▼──────┐
    │ Wazuh API │      │ Elastic-   │
    │ :55000    │      │ search     │
    │ (агенты,  │      │ :9200      │
    │  аутент.) │      │ (алерты)   │
    └───────────┘      └────────────┘
```

### Поток данных

1. **Подключение**: Браузер → Next.js → Flask → Wazuh API (JWT-токен) + ES (Basic Auth)
2. **Агенты**: Браузер → Next.js → Flask → Wazuh API `GET /agents`
3. **Алерты**: Браузер → Next.js → Flask → ES `POST /wazuh-alerts-4.x-*/_search`
4. **Анализ**: Браузер → Next.js → Flask → GraphEngine → 6× ES-запросов → граф {nodes, edges}

---

## 3. Технологический стек

| Компонент | Технология | Версия | Назначение |
|-----------|-----------|--------|-----------|
| Frontend | Next.js (App Router) | 16.x | SSR/SSG фреймворк, API-прокси |
| UI | React + TypeScript | 19.x | Компоненты интерфейса |
| Визуализация | Cytoscape.js | 3.34 | Графовая визуализация (Canvas) |
| Стили | Tailwind CSS + shadcn/ui | 4.x | Адаптивный дизайн, компоненты |
| Иконки | Lucide React | 0.525 | Иконки интерфейса |
| Backend | Python + Flask | 3.1.1 | REST API, бизнес-логика |
| HTTP-клиент | requests | 2.32.3 | Запросы к Wazuh API и ES |
| SIEM | Wazuh | 4.14.7 | Мониторинг, алерты, агенты |
| Хранилище алертов | Elasticsearch | (OpenSearch) | Индекс `wazuh-alerts-4.x-*` |
| Генерация атак | simulate_attack.py | — | Фейковые алерты для тестов |

**Выбор стека** соответствует **Варианту А** из требований диплома: Python (Flask) + Cytoscape.js + Elasticsearch (без Neo4j).

---

## 4. Структура проекта

```
graph-attack-chain/
├── src/                              # Next.js фронтенд
│   ├── app/
│   │   ├── page.tsx                  # Главный компонент
│   │   ├── globals.css               # Глобальные стили
│   │   ├── layout.tsx                # Корневой layout
│   │   └── api/                      # API-прокси маршруты
│   │       ├── wazuh/
│   │       │   ├── connect/route.ts  # POST — подключение к Wazuh
│   │       │   ├── agents/route.ts   # GET  — список агентов
│   │       │   ├── alerts/route.ts   # GET  — алерты из ES
│   │       │   └── status/route.ts   # GET  — статус подключения
│   │       └── analyze/route.ts      # POST — анализ алерта → граф
│   └── components/ui/                # shadcn/ui компоненты
│
├── mini-services/
│   └── flask-backend/                # Python Flask бэкенд
│       ├── app.py                    # Маршруты REST API
│       ├── wazuh_client.py           # Клиент Wazuh API + Elasticsearch
│       ├── graph_engine.py           # Графовый движок
│       ├── simulate_attack.py        # Генератор фейковых алертов
│       ├── start.py                  # Запуск Flask-сервера
│       └── requirements.txt          # Python-зависимости
│
├── package.json                      # Next.js зависимости
└── README.md                         # Документация (этот файл)
```

---

## 5. Установка и запуск

### Предварительные требования

- **Node.js** 18+ и **bun** (пакетный менеджер)
- **Python** 3.10+ и **pip**
- **Wazuh** 4.x (Docker или bare-metal) с запущенным Manager API и Elasticsearch/Indexer
- Доступ к Wazuh API (порт 55000) и ES (порт 9200)

### Запуск фронтенда (Next.js)

```bash
cd /path/to/graph-attack-chain
npm install
npm run 
# → http://localhost:3000
```

### Запуск бэкенда (Flask)

```bash
cd mini-services/flask-backend
pip install -r requirements.txt
python app.py
# → http://0.0.0.0:5001
```

Или альтернативно:
```bash
python start.py
```

### Генерация тестовых алертов

```bash
cd mini-services/flask-backend
python simulate_attack.py \
  --url https://<WAZUH_IP>:55000 \
  --user wazuh-wui --pass '<WAZUH_PASSWORD>' \
  --es-url https://<WAZUH_IP>:9200 \
  --es-user admin --es-pass '<ES_PASSWORD>' \
  --scenario all
```

Сценарии: `lateral_movement`, `phishing_c2`, `privilege_escalation`, `data_exfil`, `all`

---

## 6. Модули и функции — подробное описание

### 6.1 Flask Backend (app.py)

Главный файл Flask-приложения, определяет REST API маршруты.

| Маршрут | Метод | Назначение | Вход | Выход |
|---------|-------|-----------|------|-------|
| `/api/health` | GET | Проверка здоровья сервиса | — | `{status, version, wazuh_connected, es_connected}` |
| `/api/wazuh/connect` | POST | Подключение к Wazuh + ES | `{url, username, password, es_url, es_user, es_pass}` | `{version, agents_count, es}` |
| `/api/wazuh/agents` | GET | Список агентов | `?status=active` | `{agents: [{id, name, ip, status, ...}], total}` |
| `/api/wazuh/alerts` | GET | Алерты из ES | `?agent_id=001&limit=100&severity_min=0&hours=24` | `{alerts: [...], total, agent_id}` |
| `/api/analyze` | POST | Анализ алерта → граф | `{agent_id, agent_name, user_name, ...}` | `{nodes, edges, stats, query_log}` |

**Глобальные объекты:**
- `wazuh: WazuhClient` — экземпляр клиента Wazuh (создаётся при подключении)
- `engine: GraphEngine` — экземпляр графового движка (пересоздаётся при подключении)

---

### 6.2 Клиент Wazuh (wazuh_client.py)

Клиент для работы с Wazuh Manager API и Elasticsearch. Два канала связи:

1. **Wazuh API** (порт 55000) — аутентификация, список агентов, информация о менеджере
2. **Elasticsearch** (порт 9200) — поиск алертов в индексе `wazuh-alerts-4.x-*`

#### Класс `WazuhClient`

**Атрибуты:**
| Атрибут | Тип | Описание |
|---------|-----|----------|
| `base_url` | str | URL Wazuh API (напр. `https://31.77.202.176:55000`) |
| `username` | str | Имя пользователя Wazuh API |
| `password` | str | Пароль Wazuh API |
| `token` | str\|None | JWT-токен (получается при `connect()`) |
| `es_url` | str | URL Elasticsearch |
| `es_session` | Session\|None | HTTP-сессия ES (с Basic Auth) |

**Основные методы:**

| Метод | Назначение | Канал |
|-------|-----------|-------|
| `connect()` | Аутентификация в Wazuh API → JWT-токен | Wazuh API |
| `connect_es()` | Подключение к Elasticsearch (Basic Auth) | ES |
| `get_agents(status)` | Список агентов с фильтром по статусу | Wazuh API |
| `get_alerts(agents, from_time, severity_min, ...)` | Поиск алертов с фильтрами | ES |
| `search_auth_events(agent_id, user_name, ...)` | Запрос 1: аутентификация | ES |
| `search_network_connections(agent_id, ...)` | Запрос 2: сетевые соединения | ES |
| `search_related_alerts(agent_id, severity_min, ...)` | Запрос 3: связанные алерты | ES |
| `search_ip_on_other_hosts(src_ip, exclude_agent_id, ...)` | Запрос 4: латеральное движение | ES |
| `search_process_events(agent_id, process_name, ...)` | Запрос 5: события процесса | ES |
| `search_file_events(agent_id, ...)` | Запрос 6: файловые операции | ES |
| `get_alert_detail_for_graph(alert)` | Извлечение полей для графа | — |
| `_detect_category(alert)` | Определение категории алерта | — |
| `_parse_q_to_es(q)` | Парсер Wazuh query string → ES bool query | — |

---

### 6.3 Графовый движок (graph_engine.py)

Ядро инструмента — строит граф атаки на основе алерта и связанных событий.

#### Алгоритм (6 шагов)

| Шаг | Метод WazuhClient | Что ищет | Какие узлы/рёбра добавляет |
|-----|-------------------|----------|---------------------------|
| 0 | — | Исходный алерт | Хост, пользователь, IP, процесс |
| 1 | `search_auth_events` | Входы пользователя на хост | IP→Хост (auth), User→Хост (auth) |
| 2 | `search_network_connections` | Сетевые соединения с хоста | IP→IP (network), Хост→Домен (dns) |
| 3 | `search_related_alerts` | Другие алерты (severity > N) | Все сущности из найденных алертов |
| 4 | `search_ip_on_other_hosts` | События с тем же IP на других хостах | IP→Хост (network), все сущности |
| 5 | `search_process_events` | События процесса на хосте | User→Process, Хост→Process |
| 6 | `search_file_events` | Файловые операции | Process→File, User→File |

#### Типы узлов

| Тип | Цвет | Форма | Описание |
|-----|------|-------|----------|
| `ip` | 🟠 `#f97316` | ромб | IP-адрес (источник/назначение) |
| `host` | 🔵 `#3b82f6` | прямоугольник | Имя хоста/агента |
| `user` | 🟣 `#8b5cf6` | скруглённый прямоугольник | Пользователь |
| `process` | 🔴 `#ef4444` | шестиугольник | Процесс/команда |
| `file` | 🟢 `#22c55e` | треугольник | Файл/путь реестра |
| `domain` | 🟡 `#eab308` | эллипс | DNS-домен |

#### Типы рёбер

| Тип | Цвет | Описание | Пунктир |
|-----|------|----------|---------|
| `auth` | 🟣 `#8b5cf6` | Аутентификация | да |
| `process` | 🔴 `#ef4444` | Запуск процесса | нет |
| `network` | 🔵 `#3b82f6` | Сетевое соединение | нет |
| `file_op` | 🟢 `#22c55e` | Файловая операция | да |
| `registry` | 🟠 `#f97316` | Изменение реестра | да |
| `dns` | 🟡 `#eab308` | DNS-запрос | да |

#### Классы

- **`GraphNode`** — узел графа: `{id, label, type, details}` → сериализация в `{data: {id, label, type, color, shape, typeLabel, ...}}`
- **`GraphEdge`** — ребро графа: `{id, source, target, type, label, details}` → сериализация в `{data: {id, source, target, type, label, color, typeLabel, dash, ...}}`
- **`GraphEngine`** — основной класс:
  - `_add_node(id, label, type, **details)` — добавить узел (без дубликатов)
  - `_add_edge(source, target, type, label, **details)` — добавить ребро (без дубликатов)
  - `_extract_from_alert(detail)` — извлечь узлы/рёбра из одного алерта
  - `analyze_alert(alert_data)` — **главный метод**: 6 шагов → граф
  - `_build_result(initial_alert)` — сформировать итоговый JSON `{nodes, edges, stats, query_log}`

---

### 6.4 Симуляция атак (simulate_attack.py)

Скрипт для генерации фейковых алертов в Elasticsearch для тестирования инструмента.

#### Класс `AttackSimulator`

| Метод | Назначение |
|-------|-----------|
| `_wazuh_auth()` | Аутентификация в Wazuh API (GET + Basic Auth + ?raw=true) |
| `get_existing_agents()` | Получить список реальных агентов |
| `inject_alert(alert)` | Записать алерт в ES (PUT /{index}/_doc/{id}) |
| `_alert(...)` | Сформировать документ алерта в формате Wazuh |
| `_pick_agent()` | Выбрать первого не-менеджер агента |
| `scenario_lateral_movement()` | 10 алертов: RDP → SMB → PowerShell → C2 → persistence |
| `scenario_phishing_c2()` | 9 алертов: фишинг → макрос → C2-канал → heartbeat |
| `scenario_privilege_escalation()` | 5 алертов: web-shell → создание admin → mimikatz |
| `scenario_data_exfiltration()` | 5 алертов: разведка → архивация → эксфильтрация |

#### Структура Wazuh-алерта в ES

```json
{
  "@timestamp": "2026-08-03T12:00:00.000Z",
  "timestamp": "2026-08-03T12:00:00.000Z",
  "id": "1709568000.001",
  "manager": {"name": "wazuh.manager"},
  "agent": {"id": "001", "name": "wind", "ip": "172.18.0.1"},
  "rule": {"id": "5716", "level": 7, "description": "...", "groups": ["..."]},
  "full_log": "...",
  "decoder": {"name": "..."},
  "location": "...",
  "srcip": "10.0.0.50",
  "dstip": "192.168.1.10",
  "data": {"srcip": "10.0.0.50", ...}
}
```

Индекс: `wazuh-alerts-4.x-YYYY.MM.DD` (ежедневный rollover)

---

### 6.5 Фронтенд (page.tsx)

Одностраничное React-приложение с тремя состояниями:

1. **Экран подключения** — форма ввода URL/кредов Wazuh + ES
2. **Рабочее пространство** — три панели:
   - Левая: список агентов + фильтры + список алертов
   - Центр: Cytoscape.js граф + панель инструментов (zoom, fit, fullscreen, reset)
   - Правая: детали выбранного алерта/узла/ребра + журнал запросов + статистика
3. **Подвал** — информация о версии

#### React-состояния

| Группа | Переменные | Назначение |
|--------|-----------|-----------|
| Подключение | `wazuhUrl`, `wazuhUser`, `wazuhPass`, `esUrl`, `esUser`, `esPass`, `wazuhConnected`, `wazuhVersion`, `connectError`, `connecting` | Параметры и статус подключения |
| Данные | `agents`, `selectedAgent`, `alerts`, `totalAlerts`, `selectedAlert`, `severityFilter`, `hoursFilter`, `loadingAlerts` | Агенты, алерты, фильтры |
| Граф | `graphData`, `loading`, `error`, `activeStep`, `selectedNode`, `selectedEdge`, `cyReady`, `isFullscreen` | Данные графа, состояние Cytoscape |

#### Основные функции

| Функция | Назначение |
|---------|-----------|
| `handleConnect()` | POST /api/wazuh/connect → подключение, затем загрузка агентов |
| `loadAgents()` | GET /api/wazuh/agents → список агентов |
| `loadAlerts(agent)` | GET /api/wazuh/alerts → алерты для выбранного агента |
| `analyzeAlert(alert)` | POST /api/analyze → анализ алерта, построение графа |
| `loadGraph(data)` | Добавление элементов в Cytoscape, запуск layout, анимация |
| `zoomIn()`, `zoomOut()`, `fitGraph()` | Управление масштабом графа |
| `toggleFullscreen()` | Полноэкранный режим (Fullscreen API) |
| `resetGraph()` | Очистка графа и возврат к начальному состоянию |

#### Cytoscape.js — конфигурация

- **Layout**: `breadthfirst` (направленный, spacingFactor=1.2)
- **Interactions**: зум (колёсико + кнопки), панорамирование (перетаскивание), выделение узлов/рёбер
- **Стили**: 8 селекторов (node, node[?isInitial], node:selected, edge, edge:selected, .dimmed, .highlighted)
- **Event handlers**: клик по узлу → выделение связных, клик по ребру → подсветка, клик по фону → сброс

---

### 6.6 API-прокси (Next.js routes)

Next.js выступает как API-прокси между браузером и Flask-бэкендом. Все запросы пересылаются на `http://localhost:5001`.

| Файл | Маршрут | Метод | Что проксирует |
|------|---------|-------|----------------|
| `api/wazuh/connect/route.ts` | `/api/wazuh/connect` | POST | Подключение к Wazuh + ES |
| `api/wazuh/agents/route.ts` | `/api/wazuh/agents` | GET | Список агентов |
| `api/wazuh/alerts/route.ts` | `/api/wazuh/alerts` | GET | Поиск алертов в ES |
| `api/wazuh/status/route.ts` | `/api/wazuh/status` | GET | Статус подключения |
| `api/analyze/route.ts` | `/api/analyze` | POST | Анализ алерта → граф |

Все прокси обрабатывают ошибки 503 (Flask недоступен) и возвращают JSON с полем `error`.

---

## 7. Интеграция с Wazuh API — используемые эндпоинты

| Wazuh API Endpoint | Метод | Используется в | Назначение |
|--------------------|-------|----------------|-----------|
| `/security/user/authenticate?raw=true` | GET | `wazuh_client.connect()`, `simulate_attack.py` | Аутентификация → JWT-токен. **Важно**: Wazuh 4.x поддерживает только GET + Basic Auth + `?raw=true` (POST JSON возвращает 401) |
| `/` | GET | `wazuh_client.connect()` | Информация о менеджере (версия API, hostname). Требует `?pretty=true` |
| `/agents` | GET | `wazuh_client.get_agents()`, `simulate_attack.py` | Список агентов. Параметры: `limit`, `status`, `select`. **Ограничение Wazuh 4.x**: `select` не поддерживает вложенные поля (os, group) |

### Аутентификация

Wazuh 4.x API использует JWT-токены:
1. `GET /security/user/authenticate?raw=true` с Basic Auth → токен в виде plain text
2. Все последующие запросы: `Authorization: Bearer <token>`
3. Токен автоматически обновляется (Wazuh API v4 имеет короткий TTL)

### Альтернативный канал: Elasticsearch API

Алерты запрашиваются **напрямую из Elasticsearch**, а не через Wazuh API, потому что:
- Wazuh 4.x не имеет удобного endpoint для поиска алертов с фильтрами
- ES позволяет гибкий DSL-поиск (bool queries, ranges, wildcards)
- Индекс `wazuh-alerts-4.x-*` содержит все поля оригинального алерта

---

## 8. Запросы к Elasticsearch — структура и поля

### Индекс

`wazuh-alerts-4.x-YYYY.MM.DD` — ежедневно Wazuh создаёт новый индекс. Запросы идут по wildcard: `wazuh-alerts-4.x-*`.

### Основные поля Wazuh-алерта в ES

| Поле ES | Тип | Описание | Используется в |
|---------|-----|----------|----------------|
| `@timestamp` | date | Время события (ISO 8601) | Все запросы (range filter) |
| `agent.id` | keyword | ID агента (напр. "001") | Все запросы (term filter) |
| `agent.name` | keyword | Имя агента (напр. "wind") | Извлечение для графа |
| `agent.ip` | keyword | IP агента | Извлечение для графа |
| `rule.id` | keyword | ID правила Wazuh | Фильтрация по правилам |
| `rule.level` | integer | Уровень severity (0-15) | Фильтрация по severity |
| `rule.description` | text | Описание правила | Отображение в UI |
| `rule.groups` | keyword[] | Группы правил | Фильтрация по категориям (authentication, syscheck, etc.) |
| `srcip` | keyword | IP-источник | Узел IP в графе |
| `full_log` | text | Полный лог события | Отображение, поиск процесса, DNS |
| `data.auth.user` | keyword | Пользователь аутентификации | Узел User в графе |
| `data.srcuser` | keyword | Исходный пользователь | Узел User в графе |
| `data.win.eventdata.image` | keyword | Путь к исполняемому файлу (Windows) | Узел Process в графе |
| `data.win.eventdata.commandLine` | keyword | Командная строка | Атрибут Process |
| `data.win.eventdata.targetUserName` | keyword | Целевой пользователь (Windows) | Узел User |
| `data.win.eventdata.targetFilename` | keyword | Целевой файл (Windows) | Узел File |
| `data.syscheck.path` | keyword | Путь файла (syscheck) | Узел File |
| `decoder.name` | keyword | Имя декодера | Метаданные |
| `location` | keyword | Источник лога | Метаданные |

### Пример ES-запроса (поиск аутентификации)

```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"agent.id": "001"}},
        {"range": {"@timestamp": {"gte": "2026-08-03T11:00:00.000Z"}}},
        {"wildcard": {"rule.groups": "*authentication*"}}
      ]
    }
  },
  "from": 0,
  "size": 50,
  "sort": [{"@timestamp": {"order": "desc"}}]
}
```

---

## 9. Алгоритм построения графа (6 шагов)

На входе: алерт Wazuh (agent_id, user_name, process_name, src_ip, rule_description, ...)

### Шаг 0: Исходный алерт
- Создаются начальные узлы: хост, пользователь, IP-источник, процесс
- Записывается в журнал запросов

### Шаг 1: Поиск аутентификации
- **ES-запрос**: `agent.id = <agent_id> AND rule.groups = *authentication* AND @timestamp >= <now-60min>`
- **Результат**: алерты входа в систему → узлы IP, User; рёбра IP→Host (auth), User→Host (auth)
- **Цель**: определить IP-источник атаки

### Шаг 2: Сетевые соединения
- **ES-запрос**: `agent.id = <agent_id> AND rule.groups = *network*|*firewall*`
- **Результат**: сетевые алерты → узлы IP, Domain; рёбра IP→IP (network), Host→Domain (dns)
- **Цель**: выявить внешние соединения и C2-каналы

### Шаг 3: Связанные алерты
- **ES-запрос**: `agent.id = <agent_id> AND rule.level > 4`
- **Результат**: все подозрительные алерты на хосте → все извлекаемые сущности
- **Цель**: обнаружить другие аномалии на хосте

### Шаг 4: Латеральное движение
- **ES-запрос**: `srcip = <detected_src_ip> AND agent.id != <current_agent_id>`
- **Результат**: события с тем же IP на других хостах → новые узлы хостов
- **Цель**: обнаружить распространение атаки на другие системы

### Шаг 5: Анализ процесса
- **ES-запрос**: `agent.id = <agent_id> AND full_log = *<process_name>*`
- **Результат**: события процесса → рёбра User→Process, Host→Process
- **Цель**: отследить активность подозрительного процесса

### Шаг 6: Файловые операции
- **ES-запрос**: `agent.id = <agent_id> AND rule.groups = *syscheck*`
- **Результат**: файловые алерты → рёбра Process→File, User→File
- **Цель**: выявить создание/модификацию файлов

### Итоговый результат

```json
{
  "nodes": [{"data": {"id": "ip-10.0.0.50", "label": "10.0.0.50", "type": "ip", ...}}, ...],
  "edges": [{"data": {"id": "e-ip-10.0.0.50->host-wind-auth", "source": "ip-10.0.0.50", "target": "host-wind", ...}}, ...],
  "stats": {"total_nodes": 5, "total_edges": 4, "node_types": {"ip": 2, "host": 1, "user": 1, "process": 1}, "edge_types": {"auth": 1, "network": 2, "process": 1}},
  "query_log": [{"step": 1, "name": "Поиск аутентификации", "results_count": 3, ...}, ...]
}
```

---

## 10. Структура данных графа

### Узел (GraphNode)

```typescript
interface GraphNode {
  data: {
    id: string;         // Уникальный ID (напр. "ip-10.0.0.50")
    label: string;      // Отображаемая метка (напр. "10.0.0.50")
    type: string;       // Тип: ip | host | user | process | file | domain
    color: string;      // Цвет узла (hex)
    shape: string;      // Форма: diamond | rectangle | round-rectangle | hexagon | triangle | ellipse
    typeLabel: string;  // Тип на русском: "IP-адрес" | "Хост" | "Пользователь" | "Процесс" | "Файл" | "Домен"
    isInitial?: boolean;// Флаг начального узла (исходный алерт)
    ip?: string;        // IP-адрес (для типа host)
    command?: string;   // Команда (для типа process)
    full_path?: string; // Полный путь (для типа file)
    action?: string;    // Действие (для типа file)
  };
}
```

### Ребро (GraphEdge)

```typescript
interface GraphEdge {
  data: {
    id: string;         // Уникальный ID (напр. "e-ip-10.0.0.50->host-wind-auth")
    source: string;     // ID исходного узла
    target: string;     // ID целевого узла
    type: string;       // Тип: auth | process | network | file_op | registry | dns
    label: string;      // Описание ребра
    color: string;      // Цвет ребра (hex)
    typeLabel: string;  // Тип на русском: "Аутентификация" | "Запуск процесса" | ...
    dash: boolean;      // Пунктирная линия
    rule_id?: string;   // ID правила Wazuh
    severity?: number;  // Уровень severity
    timestamp?: string; // Время события
    full_log?: string;  // Полный лог
  };
}
```

---

## 11. Тестовые сценарии атак

### Сценарий 1: Латеральное движение (10 алертов)

MITRE ATT&CK: T1021.001 (RDP), T1059.001 (PowerShell), T1071.004 (DNS C2), T1547.001 (Registry Run), T1136.001 (Create Account)

| Шаг | Rule ID | Level | Описание |
|-----|---------|-------|----------|
| 1 | 5710 | 5 | RDP-подключение с внешнего IP |
| 2 | 5716 | 5 | SMB-доступ к административному шару |
| 3 | 5716 | 7 | PowerShell с -EncodedCommand |
| 4 | 5716 | 8 | Загрузка скрипта из сети |
| 5 | 5102 | 5 | DNS-запрос к C2-домену |
| 6 | 554 | 6 | Изменение реестра (Run key) |
| 7 | 592 | 8 | Создание backdoor-пользователя |
| 8 | 554 | 7 | Создание подозрительного DLL |
| 9 | 554 | 9 | Массовое копирование файлов |
| 10 | 5102 | 10 | C2-запрос с командой |

### Сценарий 2: Фишинг → C2 (9 алертов)

MITRE ATT&CK: T1566.001 (Phishing), T1059.001 (PowerShell), T1071.004 (DNS C2), T1560 (Archive)

| Шаг | Rule ID | Level | Описание |
|-----|---------|-------|----------|
| 1 | 5716 | 6 | Office-документ с макросом |
| 2 | 5102 | 5 | DNS-запрос к C2-домену |
| 3 | 5716 | 8 | PowerShell IEX-запрос |
| 4-8 | 5102 | 3-7 | C2-heartbeat (5 алертов) |
| 9 | 5716 | 9 | Сбор данных для эксфильтрации |

### Сценарий 3: Повышение привилегий (5 алертов)

MITRE ATT&CK: T1190 (Exploit Public-Facing App), T1136.001 (Create Account), T1098 (Account Manipulation), T1547.001 (Registry Run), T1003.001 (LSA Secrets)

| Шаг | Rule ID | Level | Описание |
|-----|---------|-------|----------|
| 1 | 5716 | 6 | Web-shell: whoami |
| 2 | 592 | 8 | Создание пользователя admin2 |
| 3 | 592 | 9 | Добавление в группу Administrators |
| 4 | 554 | 7 | Registry Run key persistence |
| 5 | 5716 | 10 | Скачивание mimikatz |

### Сценарий 4: Эксфильтрация данных (5 алертов)

MITRE ATT&CK: T1087.002 (Domain Account Discovery), T1560.001 (Archive via Utility), T1048 (Exfiltration Over Alternative Protocol)

| Шаг | Rule ID | Level | Описание |
|-----|---------|-------|----------|
| 1 | 5710 | 5 | RDP-подключение |
| 2 | 5716 | 5 | Разведка файловой системы (dir /s /b) |
| 3 | 5716 | 7 | Архивация (Compress-Archive) |
| 4 | 554 | 9 | Копирование архива на внешний ресурс |
| 5 | 5102 | 10 | Соединение на нестандартный порт |

---


