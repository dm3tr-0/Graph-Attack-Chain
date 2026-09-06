// ============================================================================
// page.tsx — Главная страница приложения Graph Attack Chain
// ============================================================================
//
// Архитектура:
//   Одностраничное React-приложение (Next.js App Router, 'use client')
//   для визуализации цепочек кибератак на основе данных Wazuh SIEM.
//
// Поток данных:
//   1. Пользователь подключается к Wazuh Manager API + Elasticsearch
//   2. Загружается список агентов (endpoint-ов Wazuh)
//   3. Пользователь выбирает агента → загружаются алерты
//   4. Пользователь выбирает алерт → отправляется запрос на анализ
//   5. Flask-бэкенд выполняет 6-шаговый алгоритм запросов к Elasticsearch
//   6. Результат (узлы + рёбра + статистика) визуализируется через Cytoscape.js
//
// Трёхпанельная раскладка SOC-аналитика:
//   Левая панель  — список агентов + фильтры алертов + список алертов
//   Центральная   — интерактивный граф (Cytoscape.js) + панель инструментов
//   Правая панель — детали выбранного элемента + журнал запросов + статистика
//
// Прокси-маршруты Next.js → Flask (порт 5001):
//   POST /api/wazuh/connect  — подключение к Wazuh API
//   GET  /api/wazuh/agents   — получение списка агентов
//   GET  /api/wazuh/alerts   — получение алертов по агенту
//   GET  /api/wazuh/status   — проверка статуса подключения
//   POST /api/analyze        — запуск анализа алерта (построение графа)
//
// Зависимости:
//   cytoscape      — библиотека визуализации графов
//   lucide-react   — иконки
//   @/components/ui — shadcn/ui компоненты (Button, Badge, Input, и т.д.)
// ============================================================================

'use client';

// --- Импорты React хуков ---
// useEffect   — побочные эффекты (инициализация Cytoscape, подписки на события)
// useRef      — ссылки на DOM-элементы и мутабельные объекты (контейнер графа, экземпляр cy)
// useState    — локальное состояние компонента
// useCallback — мемоизация callback-функций для предотвращения лишних рендеров
import { useEffect, useRef, useState, useCallback } from 'react';

// --- Cytoscape.js ---
// cytoscape   — фабричная функция для создания экземпляра графа
// Core        — тип экземпляра Cytoscape (доступ к elements, layout, zoom, и т.д.)
// EventObject — тип объекта события (tap, click и др.)
// NodeSingular — тип одиночного узла (для работы с данными и связями)
import cytoscape, { type Core, type EventObject, type NodeSingular } from 'cytoscape';

// --- Компоненты UI (shadcn/ui) ---
// Button      — кнопка (варианты: default, outline, ghost; размеры: sm, default)
// Badge       — значок/метка для визуальных индикаторов
// Input       — текстовое поле ввода
// Label       — подпись к полю ввода
// ScrollArea  — область с прокруткой (кастомный скроллбар)
// Separator   — разделитель (горизонтальный/вертикальный)
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';

// Select и субкомпоненты — выпадающий список для фильтров (severity, временной диапазон)
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

// --- Иконки (lucide-react) ---
// Shield       — щит (логотип, защита)
// Search       — лупа (поиск)
// Activity     — активность (статистика)
// Network      — сеть (категория network)
// User         — пользователь (категория authentication)
// FileText     — файл (категория file)
// Globe        — глобус (домен)
// Cpu          — процессор (категория registry)
// ZoomIn/Out   — масштабирование графа
// Maximize2    — подгонка графа в окно (fit)
// Loader2      — спиннер загрузки
// AlertTriangle — предупреждение (ошибки)
// Terminal     — терминал (журнал запросов)
// Plug         — подключение (Wazuh connection)
// ChevronRight — стрелка вправо (детали ребра)
// Server       — сервер (агенты)
// AlertOctagon — октаэдр (алерты)
// Eye          — глаз (выбранный алерт)
// RotateCcw    — сброс графа
import {
  Shield, Search, Activity, Network, User, FileText,
  Globe, Cpu, ZoomIn, ZoomOut, Maximize2, Loader2, AlertTriangle,
  Terminal, Plug, ChevronRight, Server, AlertOctagon, Eye, RotateCcw,
} from 'lucide-react';

// ============================================================================
// --- Типы (TypeScript интерфейсы) ---
// ============================================================================
// Описывают структуру данных, которыми обмениваются фронтенд и бэкенд.
// Все интерфейсы соответствуют JSON-ответам Flask API.

// GraphNode — узел графа атаки (IP-адрес, хост, пользователь, процесс, файл, домен)
//   data.id        — уникальный идентификатор узла (формат: "type-value", напр. "ip-10.0.0.1")
//   data.label     — отображаемая метка (IP, имя хоста, имя пользователя и т.д.)
//   data.type      — тип узла: "ip" | "host" | "user" | "process" | "file" | "domain"
//   data.color     — цвет узла (hex), зависит от типа
//   data.shape     — форма узла (для Cytoscape: rectangle, diamond, hexagon, и т.д.)
//   data.typeLabel — человекочитаемая метка типа (напр. "IP-адрес", "Процесс")
//   data.isInitial — флаг: является ли узел начальной точкой атаки (жёлтая рамка)
//   data.ip        — IP-адрес (только для узлов типа "ip" и "host")
//   data.command   — командная строка (только для узлов типа "process")
//   data.full_path — полный путь (только для узлов типа "file")
//   data.action    — действие над файлом (modified, created, deleted)
interface GraphNode {
  data: {
    id: string; label: string; type: string; color: string;
    shape: string; typeLabel: string; isInitial?: boolean;
    ip?: string; command?: string; full_path?: string; action?: string;
  };
}

// GraphEdge — ребро графа атаки (связь между узлами: аутентификация, сеть, процесс, и т.д.)
//   data.id         — уникальный идентификатор ребра
//   data.source     — ID исходного узла
//   data.target     — ID целевого узла
//   data.type       — тип ребра: "auth" | "network" | "process" | "file" | "registry" | "dns"
//   data.label      — метка ребра (напр. "SSH login", "TCP connection")
//   data.color      — цвет ребра (hex), зависит от типа
//   data.typeLabel  — человекочитаемая метка типа (напр. "Аутентификация", "Сеть")
//   data.dash       — флаг: пунктирная линия (для косвенных связей)
//   data.rule_id    — ID правила Wazuh, сгенерировавшего алерт
//   data.severity   — уровень серьёзности (0-15, шкала Wazuh)
//   data.timestamp  — время события (ISO 8601)
//   data.full_log   — полный лог события (для отображения в деталях)
interface GraphEdge {
  data: {
    id: string; source: string; target: string; type: string;
    label: string; color: string; typeLabel: string; dash: boolean;
    rule_id?: string; severity?: number; timestamp?: string; full_log?: string;
  };
}

// WazuhAgent — агент Wazuh (endpoint, контролируемый Wazuh Manager)
//   id             — ID агента (напр. "001", "002")
//   name           — имя агента (hostname)
//   ip             — IP-адрес агента
//   status         — статус: "active" | "disconnected" | "never_connected"
//   os             — операционная система
//   os_version     — версия ОС
//   last_keepalive — время последнего keepalive
//   group          — группа конфигурации агента
interface WazuhAgent {
  id: string; name: string; ip: string; status: string;
  os: string; os_version: string; last_keepalive: string; group: string;
}

// WazuhAlert — алерт Wazuh (событие безопасности, сгенерированное правилом)
//   event_id         — уникальный ID события
//   timestamp        — время алерта
//   rule_id          — ID сработавшего правила Wazuh
//   rule_description — описание правила
//   severity         — уровень серьёзности (0-15)
//   agent_id/name/ip — агент, на котором сработало правило
//   src_ip / dst_ip  — IP-адреса источника и назначения
//   user_name        — имя пользователя (если применимо)
//   process_name     — имя процесса
//   process_cmd      — командная строка процесса
//   file_path        — путь к файлу
//   file_action      — действие с файлом
//   category         — категория алерта (authentication, network, file, и т.д.)
//   full_log         — полный лог события
interface WazuhAlert {
  event_id: string; timestamp: string; rule_id: string;
  rule_description: string; severity: number; agent_id: string;
  agent_name: string; agent_ip: string; src_ip: string; dst_ip: string;
  user_name: string; process_name: string; process_cmd: string;
  file_path: string; file_action: string; category: string; full_log: string;
}

// QueryLogEntry — запись журнала запросов (один шаг 6-шагового алгоритма)
//   step          — номер шага (1-6)
//   name          — название шага (напр. "Поиск аутентификаций")
//   description   — описание запроса к Elasticsearch
//   params        — параметры запроса (фильтры, IP, user, и т.д.)
//   results_count — количество найденных результатов
//   timestamp     — время выполнения шага
interface QueryLogEntry {
  step: number; name: string; description: string;
  params: Record<string, string>; results_count: number; timestamp: string;
}

// GraphResult — результат анализа алерта (полный граф атаки)
//   nodes     — массив узлов графа
//   edges     — массив рёбер графа
//   stats     — статистика: количество узлов/рёбер по типам
//   query_log — журнал 6-шагового алгоритма запросов
interface GraphResult {
  nodes: GraphNode[]; edges: GraphEdge[];
  stats: { total_nodes: number; total_edges: number; node_types: Record<string, number>; edge_types: Record<string, number> };
  query_log: QueryLogEntry[];
}

// ============================================================================
// --- Главный компонент AttackGraphPage ---
// ============================================================================
// Одностраничный компонент с тремя состояниями:
//   1. Экран подключения (если wazuhConnected === false)
//   2. Рабочее пространство с тремя панелями (если wazuhConnected === true)
//
// Жизненный цикл:
//   Монтирование → инициализация Cytoscape (useEffect с пустым deps)
//   Клик на агент → загрузка алертов → рендер списка
//   Клик на алерт → анализ → загрузка графа → Cytoscape.add() → layout → fit
//   Клик на узел/ребро → подсветка связей → отображение деталей
//   Размонтирование → cy.destroy() (очистка Cytoscape)
export default function AttackGraphPage() {
  // --- Ссылки на DOM и экземпляры ---
  // containerRef — ссылка на <div> контейнер, куда Cytoscape рендерит canvas
  const containerRef = useRef<HTMLDivElement>(null);
  // cyRef — мутабельная ссылка на экземпляр Cytoscape Core
  // Позволяет обращаться к графу из callback-функций без пересоздания
  const cyRef = useRef<Core | null>(null);

  // ============================================================================
  // --- Состояние: Подключение к Wazuh ---
  // ============================================================================
  // Поля формы подключения к Wazuh Manager API
  const [wazuhUrl, setWazuhUrl] = useState('https://');    // URL Wazuh API (напр. https://192.168.1.50:55000)
  const [wazuhUser, setWazuhUser] = useState('wazuh-wui'); // Имя пользователя Wazuh API
  const [wazuhPass, setWazuhPass] = useState('');          // Пароль пользователя Wazuh API
  const [wazuhConnected, setWazuhConnected] = useState(false); // Флаг успешного подключения
  const [wazuhVersion, setWazuhVersion] = useState('');    // Версия Wazuh API (напр. "4.9.1")

  // Поля формы подключения к Elasticsearch / Wazuh Indexer
  // ES нужен для выполнения запросов к алертам (Elasticsearch _search API)
  const [esUrl, setEsUrl] = useState('https://');  // URL Elasticsearch (напр. https://192.168.1.50:9200)
  const [esUser, setEsUser] = useState('admin');   // Имя пользователя ES
  const [esPass, setEsPass] = useState('');        // Пароль ES

  // Состояния процесса подключения
  const [connectError, setConnectError] = useState(''); // Текст ошибки подключения
  const [connecting, setConnecting] = useState(false);  // Флаг: идёт подключение (показ спиннера)

  // ============================================================================
  // --- Состояние: Данные (агенты + алерты) ---
  // ============================================================================
  const [agents, setAgents] = useState<WazuhAgent[]>([]);         // Список агентов Wazuh
  const [selectedAgent, setSelectedAgent] = useState<WazuhAgent | null>(null); // Выбранный агент (для загрузки алертов)
  const [alerts, setAlerts] = useState<WazuhAlert[]>([]);        // Список алертов выбранного агента
  const [totalAlerts, setTotalAlerts] = useState(0);             // Общее количество алертов (до пагинации)
  const [selectedAlert, setSelectedAlert] = useState<WazuhAlert | null>(null); // Выбранный алерт (для анализа)
  const [severityFilter, setSeverityFilter] = useState('0');     // Минимальный уровень серьёзности (фильтр)
  const [hoursFilter, setHoursFilter] = useState('24');          // Временное окно в часах (фильтр)
  const [loadingAlerts, setLoadingAlerts] = useState(false);     // Флаг: идёт загрузка алертов

  // ============================================================================
  // --- Состояние: Граф атаки ---
  // ============================================================================
  const [graphData, setGraphData] = useState<GraphResult | null>(null); // Результат анализа (узлы, рёбра, статистика, лог)
  const [loading, setLoading] = useState(false);                       // Флаг: идёт анализ алерта
  const [error, setError] = useState<string | null>(null);             // Текст ошибки анализа
  const [activeStep, setActiveStep] = useState(0);                     // Текущий шаг анимации запросов (1-6)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);   // Выбранный узел графа (для деталей)
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);   // Выбранное ребро графа (для деталей)

  // ============================================================================
  // --- Обработчик: Подключение к Wazuh ---
  // ============================================================================
  // handleConnect — отправляет POST /api/wazuh/connect с URL + учётными данными
  //   Wazuh Manager API и Elasticsearch.
  //   При успехе: устанавливает wazuhConnected=true, сохраняет версию,
  //   автоматически загружает список агентов.
  //   При ошибке: отображает текст ошибки в форме.
  const handleConnect = async () => {
    setConnecting(true);   // Показать спиннер
    setConnectError('');   // Сбросить предыдущую ошибку
    try {
      // POST-запрос к Next.js API-маршруту, который проксирует к Flask
      const res = await fetch('/api/wazuh/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: wazuhUrl, username: wazuhUser, password: wazuhPass,
          es_url: esUrl, es_user: esUser, es_pass: esPass,
        }),
      });
      const data = await res.json();
      // Проверка на ошибку от бэкенда (напр. неверный URL, отказ аутентификации)
      if (data.error) { setConnectError(data.error); return; }
      // Успешное подключение
      setWazuhConnected(true);
      setWazuhVersion(data.version || '');
      // Если есть агенты — загрузить их автоматически
      if (data.agents_count > 0) {
        await loadAgents();
      }
    } catch (e) {
      // Сетевая ошибка (Flask-бэкенд недоступен)
      setConnectError(e instanceof Error ? e.message : 'Ошибка подключения к бэкенду');
    } finally {
      setConnecting(false); // Скрыть спиннер
    }
  };

  // ============================================================================
  // --- Загрузка списка агентов ---
  // ============================================================================
  // loadAgents — GET /api/wazuh/agents
  //   Получает список зарегистрированных агентов Wazuh.
  //   Агенты — это endpoint-ы (серверы/рабочие станции), контролируемые Wazuh Manager.
  //   Каждый агент имеет ID, имя, IP, статус, ОС.
  const loadAgents = async () => {
    try {
      const res = await fetch('/api/wazuh/agents');
      const data = await res.json();
      if (data.agents) setAgents(data.agents);
    } catch {}
  };

  // ============================================================================
  // --- Загрузка алертов для выбранного агента ---
  // ============================================================================
  // loadAlerts — GET /api/wazuh/alerts?agent_id=...&severity_min=...&hours=...&limit=100
  //   Мемоизирован через useCallback; зависимости: severityFilter, hoursFilter
  //   (пересоздаётся при изменении фильтров, чтобы актуальные значения попадали в URL).
  //
  //   Параметры:
  //     agent       — объект WazuhAgent (для извлечения agent.id)
  //     severityFilter — минимальный уровень серьёзности (из состояния)
  //     hoursFilter    — временное окно в часах (из состояния)
  //     limit=100      — максимальное количество алертов
  //
  //   При успехе: обновляет alerts и totalAlerts
  //   При ошибке: очищает список алертов
  const loadAlerts = useCallback(async (agent: WazuhAgent) => {
    setLoadingAlerts(true);        // Показать спиннер загрузки
    setSelectedAgent(agent);       // Запомнить выбранный агент
    setSelectedAlert(null);        // Сбросить выбранный алерт
    setAlerts([]);                 // Очистить текущий список
    try {
      // Формирование query-параметров для API-запроса
      const params = new URLSearchParams({
        agent_id: agent.id,
        severity_min: severityFilter,
        hours: hoursFilter,
        limit: '100',
      });
      const res = await fetch(`/api/wazuh/alerts?${params}`);
      const data = await res.json();
      if (data.alerts) {
        setAlerts(data.alerts);          // Обновить список алертов
        setTotalAlerts(data.total || 0); // Обновить общее количество
      } else if (data.error) {
        setAlerts([]); // Ошибка от бэкенда — очистить список
      }
    } catch {}
    finally {
      setLoadingAlerts(false); // Скрыть спиннер
    }
  }, [severityFilter, hoursFilter]); // Рекреация при изменении фильтров

  // ============================================================================
  // --- Анализ алерта (построение графа атаки) ---
  // ============================================================================
  // analyzeAlert — POST /api/analyze
  //   Отправляет данные выбранного алерта на Flask-бэкенд.
  //   Бэкенд выполняет 6-шаговый алгоритм запросов к Elasticsearch:
  //     1. Поиск аутентификационных событий (same user, same agent)
  //     2. Поиск сетевых соединений (same src/dst IP)
  //     3. Поиск связанных алертов (same rule, same IPs)
  //     4. Поиск lateral movement (IP на других хостах)
  //     5. Поиск событий процессов (same agent, time window)
  //     6. Поиск файловых операций (same agent, time window)
  //
  //   Тело запроса содержит: agent_id, agent_name, agent_ip, user_name,
  //     process_name, process_cmd, src_ip, rule_id, rule_description,
  //     severity, category, full_log, time_window_min=60
  //
  //   При успехе: вызывает loadGraph() для рендеринга графа в Cytoscape
  //   При ошибке: отображает текст ошибки
  const analyzeAlert = useCallback(async (alert: WazuhAlert) => {
    setLoading(true);        // Показать спиннер анализа
    setError(null);          // Сбросить ошибку
    setGraphData(null);      // Очистить предыдущий граф
    setSelectedAlert(alert); // Запомнить выбранный алерт
    try {
      // POST-запрос к Next.js API-маршруту, который проксирует к Flask /api/analyze
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_id: alert.agent_id,
          agent_name: alert.agent_name,
          agent_ip: alert.agent_ip,
          user_name: alert.user_name,
          process_name: alert.process_name,
          process_cmd: alert.process_cmd,
          src_ip: alert.src_ip,
          rule_id: alert.rule_id,
          rule_description: alert.rule_description,
          severity: alert.severity,
          category: alert.category,
          full_log: alert.full_log,
          time_window_min: 60, // Временное окно для поиска связанных событий (60 минут)
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      const data: GraphResult = await res.json();
      setGraphData(data);             // Сохранить результат анализа
      await loadGraph(data);          // Рендер графа в Cytoscape
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Ошибка');
    } finally {
      setLoading(false); // Скрыть спиннер
    }
  }, []);

  // ============================================================================
  // --- Инициализация Cytoscape.js (useEffect) ---
  // ============================================================================
  // Выполняется один раз при монтировании компонента (deps = []).
  // Создаёт экземпляр Cytoscape с:
  //   - Пустым набором элементов (elements: [])
  //   - Кастомными стилями для узлов и рёбер
  //   - Обработчиками событий: tap на узел, tap на ребро, tap на фон
  //   - Макетом breadthfirst (иерархический, направленный)
  //
  // При размонтировании вызывает cy.destroy() для очистки ресурсов.
  useEffect(() => {
    if (!containerRef.current) return; // DOM-контейнер ещё не готов
    if (cyRef.current) cyRef.current.destroy(); // Уничтожить предыдущий экземпляр

    // --- Создание экземпляра Cytoscape ---
    const cy = cytoscape({
      container: containerRef.current, // DOM-элемент для рендеринга
      elements: [],                    // Начальный набор пуст — граф загрузится позже
      // ======================================================================
      // Стили Cytoscape (CSS-like декларации)
      // ======================================================================
      // Стили определяют визуальное представление узлов и рёбер.
      // Используется data-driven подход: цвет, метка берутся из data() узла/ребра.
      style: [
        // --- Базовый стиль узлов ---
        // Все узлы по умолчанию: метка по центру, моноширинный шрифт 10px,
        // текст с контуром (outline) для читаемости на тёмном фоне,
        // цвет фона = data(color), размер 40x40, полупрозрачная рамка.
        { selector: 'node', style: {
          'label': 'data(label)',          // Метка = data.label узла
          'text-valign': 'center',         // Вертикальное выравнивание текста
          'text-halign': 'center',         // Горизонтальное выравнивание текста
          'font-size': '10px',             // Размер шрифта
          'font-family': 'monospace',      // Моноширинный шрифт для IP, путей
          'color': '#e2e8f0',              // Цвет текста (светло-серый)
          'text-outline-width': 2,         // Толщина контура текста
          'text-outline-color': '#0f172a', // Цвет контура (тёмно-синий фон)
          'background-color': 'data(color)', // Цвет фона узла из data.color
          'width': 40,                     // Ширина узла
          'height': 40,                    // Высота узла
          'border-width': 2,              // Толщина рамки
          'border-color': 'data(color)',   // Цвет рамки = цвет фона
          'border-opacity': 0.3,           // Полупрозрачная рамка
          'opacity': 0.9,                  // Общая непрозрачность
        }},
        // --- Начальный узел атаки (isInitial = true) ---
        // Жёлтая рамка 3px, увеличенный размер 50x50 для визуального выделения
        { selector: 'node[?isInitial]', style: { 'border-width': 3, 'border-color': '#fbbf24', 'border-opacity': 1, 'width': 50, 'height': 50 }},
        // --- Выбранный узел ---
        // Жёлтая рамка 3px, полная непрозрачность
        { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#fbbf24', 'border-opacity': 1, 'opacity': 1 }},
        // --- Базовый стиль рёбер ---
        // Направленные рёбра (стрелка к target), bezier-кривые,
        // метка = typeLabel (напр. "SSH", "TCP"), авторотация текста
        { selector: 'edge', style: {
          'width': 2,                         // Толщина линии
          'line-color': 'data(color)',        // Цвет линии из data.color
          'target-arrow-color': 'data(color)', // Цвет стрелки = цвет линии
          'target-arrow-shape': 'triangle',    // Форма стрелки
          'curve-style': 'bezier',            // Стиль кривой (безье)
          'arrow-scale': 0.8,                 // Масштаб стрелки
          'opacity': 0.6,                     // Полупрозрачность (незаметные по умолчанию)
          'label': 'data(typeLabel)',          // Метка ребра (напр. "Аутентификация")
          'font-size': '8px',                 // Размер шрифта метки
          'font-family': 'sans-serif',        // Шрифт метки
          'color': '#94a3b8',                 // Цвет текста метки
          'text-rotation': 'autorotate',       // Автоповорот текста вдоль ребра
          'text-background-color': '#0f172a', // Фон текста (для читаемости)
          'text-background-opacity': 0.8,     // Непрозрачность фона текста
          'text-background-padding': '2px',   // Отступ фона текста
          'text-outline-width': 0,            // Без контура текста
        }},
        // --- Выбранное ребро ---
        // Утолщение линии, полная непрозрачность
        { selector: 'edge:selected', style: { 'width': 3, 'opacity': 1 }},
        // --- Класс "dimmed" (приглушённый) ---
        // Применяется к нескрытым элементам при выделении узла/ребра
        { selector: '.dimmed', style: { 'opacity': 0.15 }},
        // --- Класс "highlighted" (выделенный) ---
        // Полная непрозрачность для выбранных и связанных элементов
        { selector: '.highlighted', style: { 'opacity': 1 }},
      ],
      // --- Начальный макет ---
      // breadthfirst — иерархический макет от корневого узла (начальная точка атаки)
      // spacingFactor=1.5 — увеличенный отступ между узлами
      // directed=true — учитывать направление рёбер
      layout: { name: 'breadthfirst', spacingFactor: 1.5, directed: true },
      // --- Интерактивность ---
      userZoomingEnabled: true,   // Пользователь может масштабировать (колёсико мыши)
      userPanningEnabled: true,   // Пользователь может панорамировать (перетаскивание)
      boxSelectionEnabled: false, // Выделение рамкой отключено (клики вместо этого)
    });

    // ========================================================================
    // Обработчики событий Cytoscape
    // ========================================================================

    // --- Клик по узлу ---
    // 1. Извлекает данные узла и устанавливает selectedNode
    // 2. Сбрасывает selectedEdge (одновременно может быть выбран только один элемент)
    // 3. Подсвечивает узел и все связанные рёбра/узлы, остальные — dimmed
    cy.on('tap', 'node', (evt: EventObject) => {
      const node = evt.target as NodeSingular;
      const d = node.data();
      // Формирование объекта selectedNode (только нужные поля для панели деталей)
      setSelectedNode({ data: { id: d.id, label: d.label, type: d.type, color: d.color, shape: d.shape, typeLabel: d.typeLabel, ip: d.ip, command: d.command, full_path: d.full_path, action: d.action }});
      setSelectedEdge(null); // Сбросить выбранное ребро
      highlightConnected(node); // Подсветка связей узла
    });

    // --- Клик по ребру ---
    // 1. Извлекает данные ребра и устанавливает selectedEdge
    // 2. Сбрасывает selectedNode
    // 3. Подсвечивает ребро и его source/target узлы, остальные — dimmed
    cy.on('tap', 'edge', (evt: EventObject) => {
      const e = evt.target; const d = e.data();
      // Формирование объекта selectedEdge (все поля для панели деталей)
      setSelectedEdge({ data: { id: d.id, source: d.source, target: d.target, type: d.type, label: d.label, color: d.color, typeLabel: d.typeLabel, dash: d.dash, rule_id: d.rule_id, severity: d.severity, timestamp: d.timestamp, full_log: d.full_log }});
      setSelectedNode(null); // Сбросить выбранный узел
      resetHighlight();      // Сбросить все подсветки
      // Применить dimmed ко всем элементам, затем выделить ребро и его концы
      cy.elements().addClass('dimmed');
      e.addClass('highlighted');       // Выделить ребро
      e.source().addClass('highlighted'); // Выделить исходный узел
      e.target().addClass('highlighted'); // Выделить целевой узел
    });

    // --- Клик по фону графа ---
    // Если клик пришёлся на холст (не на узел/ребро) — сбросить выделение
    cy.on('tap', (evt: EventObject) => { if (evt.target === cy) { setSelectedNode(null); setSelectedEdge(null); resetHighlight(); } });

    // Сохранить экземпляр Cytoscape в ref для доступа из других функций
    cyRef.current = cy;

    // --- Очистка при размонтировании ---
    // Уничтожает экземпляр Cytoscape и обнуляет ref
    return () => { cy.destroy(); cyRef.current = null; };
  }, []); // Пустой массив зависимостей — выполняется только при монтировании

  // ============================================================================
  // --- Вспомогательные функции для подсветки ---
  // ============================================================================

  // highlightConnected — подсвечивает узел и все связанные с ним рёбра и узлы
  //   1. Применяет класс "dimmed" ко ВСЕМ элементам (opacity: 0.15)
  //   2. Применяет класс "highlighted" к выбранному узлу (opacity: 1)
  //   3. Применяет "highlighted" ко всем рёбрам, инцидентным узлу
  //   4. Применяет "highlighted" ко всем узлам на концах этих рёбер
  //   Результат: выбранная «звезда» видна, остальной граф приглушён
  const highlightConnected = (node: NodeSingular) => { const cy = cyRef.current; if (!cy) return; cy.elements().addClass('dimmed'); node.addClass('highlighted'); node.connectedEdges().addClass('highlighted'); node.connectedEdges().connectedNodes().addClass('highlighted'); };

  // resetHighlight — снимает классы "dimmed" и "highlighted" со всех элементов
  //   Возвращает граф к нормальному состоянию (все элементы на default opacity)
  const resetHighlight = () => { cyRef.current?.elements().removeClass('dimmed highlighted'); };

  // ============================================================================
  // --- Загрузка графа в Cytoscape ---
  // ============================================================================
  // loadGraph — принимает GraphResult от бэкенда и:
  //   1. Очищает предыдущий граф (cy.elements().remove())
  //   2. Сбрасывает подсветки и выделения
  //   3. Добавляет узлы и рёбра (cy.add())
  //   4. Анимирует шаги запросов (activeStep от 1 до N с задержкой 300ms)
  //      — это создаёт эффект «пошагового построения» графа в журнале
  //   5. Запускает макет breadthfirst с анимацией (600ms)
  //   6. Подгоняет граф в окно (cy.fit с отступом 50px)
  const loadGraph = useCallback(async (data: GraphResult) => {
    const cy = cyRef.current; if (!cy) return;
    // Очистка предыдущего графа
    cy.elements().remove(); resetHighlight(); setSelectedNode(null); setSelectedEdge(null);
    // Добавление новых элементов (узлы + рёбра)
    cy.add([...data.nodes, ...data.edges]);
    // Анимация шагов запросов (для журнала в правой панели)
    // Каждый шаг появляется с задержкой 300мс — эффект «построения»
    const totalSteps = data.query_log.length;
    for (let s = 1; s <= totalSteps; s++) { await new Promise<void>(r => setTimeout(r, 300)); setActiveStep(s); }
    // Запуск иерархического макета с анимацией
    cy.layout({ name: 'breadthfirst', spacingFactor: 1.2, directed: true, animate: true, animationDuration: 600 }).run();
    // Подгонка графа в видимую область с отступом 50px
    cy.fit(undefined, 50);
  }, []);

  // ============================================================================
  // --- Управление масштабом графа ---
  // ============================================================================
  // zoomIn  — увеличение масштаба в 1.3 раза
  const zoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.3);
  // zoomOut — уменьшение масштаба в 0.7 раза
  const zoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.7);
  // fitGraph — подгонка всего графа в видимую область (padding 50px)
  const fitGraph = () => cyRef.current?.fit(undefined, 50);
  // resetGraph — полная очистка графа и возврат к начальному состоянию
  //   Удаляет все элементы, сбрасывает graphData, выделения, шаги, подсветки
  const resetGraph = () => { cyRef.current?.elements().remove(); setGraphData(null); setSelectedNode(null); setSelectedEdge(null); setActiveStep(0); resetHighlight(); setSelectedAlert(null); };

  // ============================================================================
  // --- Вспомогательные функции рендера ---
  // ============================================================================

  // severityColor — возвращает CSS-класс для индикатора серьёзности
  //   Шкала Wazuh: 0-3 = низкий (синий), 4-6 = средний (жёлтый),
  //                7-9 = высокий (оранжевый), 10+ = критический (красный)
  const severityColor = (s: number) => s >= 10 ? 'bg-red-500' : s >= 7 ? 'bg-orange-500' : s >= 4 ? 'bg-yellow-500' : 'bg-blue-500';

  // categoryIcon — возвращает иконку для категории алерта
  //   authentication → User, network → Network, file → FileText,
  //   registry → Cpu, всё остальное → Terminal
  const categoryIcon = (cat: string) => {
    switch (cat) { case 'authentication': return <User className="w-3.5 h-3.5" />; case 'network': return <Network className="w-3.5 h-3.5" />; case 'file': return <FileText className="w-3.5 h-3.5" />; case 'registry': return <Cpu className="w-3.5 h-3.5" />; default: return <Terminal className="w-3.5 h-3.5" />; }
  };

  // ============================================================================
  // --- Рендер JSX ---
  // ============================================================================
  // Два основных режима:
  //   1. Экран подключения (wazuhConnected === false)
  //   2. Рабочее пространство с тремя панелями (wazuhConnected === true)
  return (
    // Корневой контейнер: полноэкранный, тёмный фон (#0a0e1a), вертикальный flex
    <div className="min-h-screen flex flex-col bg-[#0a0e1a]">

      {/* ================================================================== */}
      {/* Шапка (Header)                                                     */}
      {/* Логотип + название приложения + статус подключения к Wazuh          */}
      {/* ================================================================== */}
      <header className="flex items-center justify-between px-4 py-3 border-b border-slate-700/50 bg-[#0d1220]">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-emerald-400" />
          <div>
            <h1 className="text-sm font-bold text-slate-100 tracking-wide">Graph Attack Chain</h1>
            <p className="text-[10px] text-slate-500">Визуализация цепочек атак — Wazuh SIEM</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {/* Индикатор подключения: зелёная иконка + версия Wazuh */}
          {wazuhConnected && (
            <div className="flex items-center gap-1.5 text-xs text-emerald-400">
              <Plug className="w-3.5 h-3.5" />
              <span>Wazuh {wazuhVersion}</span>
            </div>
          )}
        </div>
      </header>

      {/* ================================================================== */}
      {/* Основная область (Main)                                            */}
      {/* ================================================================== */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {!wazuhConnected ? (
          // ==================================================================
          // ЭКРАН ПОДКЛЮЧЕНИЯ
          // ==================================================================
          // Центрированная форма для ввода URL + учётных данных
          // Wazuh Manager API и Elasticsearch.
          // Отображается только если wazuhConnected === false.
          <div className="flex-1 flex items-center justify-center p-6">
            <div className="w-full max-w-md space-y-6">
              {/* Логотип и заголовок */}
              <div className="text-center space-y-2">
                <Shield className="w-16 h-16 text-emerald-400 mx-auto" />
                <h2 className="text-xl font-bold text-slate-100">Подключение к Wazuh</h2>
                <p className="text-sm text-slate-400">Введите параметры подключения к Wazuh Manager API</p>
              </div>

              {/* --- Форма подключения --- */}
              <div className="space-y-3 bg-[#111827] p-5 rounded-xl border border-slate-700/50">
                {/* Секция: Wazuh Manager API */}
                <div className="text-xs font-medium text-emerald-400 uppercase tracking-wider">Wazuh Manager API</div>
                {/* Поле: URL Wazuh API */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-slate-400">Wazuh API URL</Label>
                  <Input value={wazuhUrl} onChange={e => setWazuhUrl(e.target.value)} placeholder="https://192.168.1.50:55000" className="bg-slate-800 border-slate-600 text-slate-200 text-sm h-9" />
                </div>
                {/* Поля: Пользователь + Пароль (в 2 колонки) */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-400">Пользователь</Label>
                    <Input value={wazuhUser} onChange={e => setWazuhUser(e.target.value)} className="bg-slate-800 border-slate-600 text-slate-200 text-sm h-9" />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-400">Пароль</Label>
                    <Input type="password" value={wazuhPass} onChange={e => setWazuhPass(e.target.value)} className="bg-slate-800 border-slate-600 text-slate-200 text-sm h-9" />
                  </div>
                </div>

                <Separator className="my-2" />

                {/* Секция: Elasticsearch / Wazuh Indexer */}
                {/* ES нужен Flask-бэкенду для выполнения _search запросов к алертам */}
                <div className="text-xs font-medium text-amber-400 uppercase tracking-wider">Elasticsearch / Indexer</div>
                {/* Поле: URL Elasticsearch */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-slate-400">Elasticsearch URL</Label>
                  <Input value={esUrl} onChange={e => setEsUrl(e.target.value)} placeholder="https://192.168.1.50:9200" className="bg-slate-800 border-slate-600 text-slate-200 text-sm h-9" />
                </div>
                {/* Поля: Пользователь + Пароль ES (в 2 колонки) */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-400">Пользователь</Label>
                    <Input value={esUser} onChange={e => setEsUser(e.target.value)} className="bg-slate-800 border-slate-600 text-slate-200 text-sm h-9" />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-400">Пароль</Label>
                    <Input type="password" value={esPass} onChange={e => setEsPass(e.target.value)} className="bg-slate-800 border-slate-600 text-slate-200 text-sm h-9" />
                  </div>
                </div>

                {/* Сообщение об ошибке подключения */}
                {connectError && (
                  <div className="flex items-start gap-2 p-2.5 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400">
                    <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                    <span>{connectError}</span>
                  </div>
                )}

                {/* Кнопка "Подключиться" */}
                {/* Отключена, если не заполнены все поля или идёт подключение */}
                <Button onClick={handleConnect} disabled={connecting || !wazuhUrl || !wazuhUser || !wazuhPass || !esUrl || !esUser || !esPass}
                  className="w-full h-9 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium">
                  {connecting ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Подключение...</> : <><Plug className="w-4 h-4 mr-2" />Подключиться</>}
                </Button>
              </div>
            </div>
          </div>
        ) : (
          // ==================================================================
          // РАБОЧЕЕ ПРОСТРАНСТВО (3-панельная раскладка)
          // ==================================================================
          // Левая панель: агенты + алерты (w-72 = 288px, фиксированная ширина)
          // Центр: граф Cytoscape (flex-1, занимает оставшееся пространство)
          // Правая панель: детали + журнал + статистика (w-80 = 320px)
          <div className="flex-1 flex overflow-hidden">

            {/* ============================================================== */}
            {/* ЛЕВАЯ ПАНЕЛЬ — Агенты и Алерты                                */}
            {/* ============================================================== */}
            <div className="w-72 border-r border-slate-700/50 flex flex-col bg-[#0d1220] shrink-0">

              {/* --- Секция: Список агентов --- */}
              {/* Каждый агент — кнопка; клик загружает алерты для этого агента */}
              <div className="p-3 border-b border-slate-700/30">
                <div className="flex items-center gap-2 mb-2">
                  <Server className="w-4 h-4 text-blue-400" />
                  <span className="text-xs font-semibold text-slate-300">Агенты ({agents.length})</span>
                </div>
                <ScrollArea className="max-h-36 overflow-y-auto">
                  {agents.length === 0 && <p className="text-[10px] text-slate-600">Нет активных агентов</p>}
                  {/* Рендер списка агентов */}
                  {agents.map(a => (
                    // Кнопка агента: клик → loadAlerts(a)
                    // Подсвечивается, если агент выбран (selectedAgent?.id === a.id)
                    <button key={a.id} onClick={() => loadAlerts(a)}
                      className={`w-full text-left px-2.5 py-1.5 rounded-md text-xs mb-0.5 transition-colors ${selectedAgent?.id === a.id ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-300'}`}>
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-medium">{a.name}</span>
                        <span className="text-[9px] text-slate-600">{a.id}</span>
                      </div>
                      <div className="text-[10px] text-slate-600 mt-0.5">{a.ip} · {a.os || '?'}</div>
                    </button>
                  ))}
                </ScrollArea>
              </div>

              {/* --- Секция: Фильтры алертов --- */}
              {/* Два выпадающих списка: минимальный severity и временное окно */}
              <div className="p-3 border-b border-slate-700/30">
                <div className="flex items-center gap-2 mb-2">
                  <AlertOctagon className="w-4 h-4 text-orange-400" />
                  <span className="text-xs font-semibold text-slate-300">Алерты {totalAlerts > 0 && <span className="text-slate-500">({totalAlerts})</span>}</span>
                </div>
                <div className="flex gap-2 mb-2">
                  {/* Фильтр: минимальный уровень серьёзности */}
                  <Select value={severityFilter} onValueChange={setSeverityFilter}>
                    <SelectTrigger className="h-7 text-[10px] bg-slate-800 border-slate-700">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="0">Все severity</SelectItem>
                      <SelectItem value="3">&gt; 3 (средние)</SelectItem>
                      <SelectItem value="5">&gt; 5 (высокие)</SelectItem>
                      <SelectItem value="7">&gt; 7 (критические)</SelectItem>
                      <SelectItem value="10">&gt; 10 (экстр.)</SelectItem>
                    </SelectContent>
                  </Select>
                  {/* Фильтр: временное окно (часы) */}
                  <Select value={hoursFilter} onValueChange={setHoursFilter}>
                    <SelectTrigger className="h-7 text-[10px] bg-slate-800 border-slate-700">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">1 час</SelectItem>
                      <SelectItem value="6">6 часов</SelectItem>
                      <SelectItem value="24">24 часа</SelectItem>
                      <SelectItem value="72">3 дня</SelectItem>
                      <SelectItem value="168">7 дней</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {/* Кнопка обновления алертов с текущими фильтрами */}
                {selectedAgent && (
                  <Button size="sm" variant="outline" onClick={() => loadAlerts(selectedAgent)} className="w-full h-7 text-[10px] border-slate-700 text-slate-400">
                    <Search className="w-3 h-3 mr-1" />Загрузить алерты
                  </Button>
                )}
              </div>

              {/* --- Секция: Список алертов --- */}
              {/* Каждый алерт — кнопка; клик запускает анализ (analyzeAlert) */}
              {/* Показывает: описание правила, severity, rule_id, user, timestamp */}
              <div className="flex-1 overflow-hidden">
                <ScrollArea className="h-full p-2">
                  {/* Спиннер загрузки */}
                  {loadingAlerts && <div className="flex items-center justify-center py-6"><Loader2 className="w-5 h-5 text-slate-500 animate-spin" /></div>}
                  {/* Нет алертов */}
                  {!loadingAlerts && alerts.length === 0 && selectedAgent && (
                    <p className="text-[10px] text-slate-600 text-center py-6">Нет алертов</p>
                  )}
                  {/* Агент не выбран */}
                  {!loadingAlerts && !selectedAgent && (
                    <p className="text-[10px] text-slate-600 text-center py-6">Выберите агента</p>
                  )}
                  {/* Рендер списка алертов */}
                  {alerts.map((a, i) => (
                    // Кнопка алерта: клик → analyzeAlert(a)
                    // Подсвечивается, если алерт выбран (selectedAlert?.event_id === a.event_id)
                    <button key={`${a.event_id}-${i}`} onClick={() => analyzeAlert(a)}
                      className={`w-full text-left px-2 py-2 rounded-lg mb-1 transition-colors group ${selectedAlert?.event_id === a.event_id ? 'bg-blue-500/20 border border-blue-500/30' : 'hover:bg-slate-800/80 border border-transparent'}`}>
                      <div className="flex items-start gap-2">
                        {/* Цветной индикатор серьёзности */}
                        <div className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${severityColor(a.severity)}`} />
                        <div className="min-w-0 flex-1">
                          {/* Описание правила */}
                          <p className="text-[11px] text-slate-300 truncate">{a.rule_description}</p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[9px] text-slate-600">L{a.severity}</span>
                            <span className="text-[9px] text-slate-600">Rule {a.rule_id}</span>
                            {a.user_name && <span className="text-[9px] text-slate-500">{a.user_name}</span>}
                          </div>
                          {/* Timestamp */}
                          <p className="text-[9px] text-slate-600 mt-0.5 truncate max-w-full">{a.timestamp?.replace('T', ' ').slice(0, 19)}</p>
                        </div>
                      </div>
                    </button>
                  ))}
                </ScrollArea>
              </div>
            </div>

            {/* ============================================================== */}
            {/* ЦЕНТРАЛЬНАЯ ПАНЕЛЬ — Граф атаки (Cytoscape.js)                */}
            {/* ============================================================== */}
            <div className="flex-1 flex flex-col min-w-0">

              {/* --- Панель инструментов графа --- */}
              {/* Кнопки: ZoomIn, ZoomOut, Fit, Reset + индикаторы состояния */}
              <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-700/30 bg-[#0d1220]">
                {/* Масштабирование */}
                <Button size="sm" variant="ghost" onClick={zoomIn} className="h-7 w-7 p-0 text-slate-400 hover:text-slate-200"><ZoomIn className="w-4 h-4" /></Button>
                <Button size="sm" variant="ghost" onClick={zoomOut} className="h-7 w-7 p-0 text-slate-400 hover:text-slate-200"><ZoomOut className="w-4 h-4" /></Button>
                {/* Подгонка в окно */}
                <Button size="sm" variant="ghost" onClick={fitGraph} className="h-7 w-7 p-0 text-slate-400 hover:text-slate-200"><Maximize2 className="w-4 h-4" /></Button>
                {/* Сброс графа (красный при hover) */}
                <Button size="sm" variant="ghost" onClick={resetGraph} className="h-7 w-7 p-0 text-slate-400 hover:text-red-400"><RotateCcw className="w-4 h-4" /></Button>
                <Separator orientation="vertical" className="h-4 bg-slate-700" />
                {/* Индикатор анализа (спиннер + текст) */}
                {loading && <><Loader2 className="w-4 h-4 text-blue-400 animate-spin" /><span className="text-xs text-blue-400">Анализ...</span></>}
                {/* Индикатор ошибки */}
                {error && <span className="text-xs text-red-400 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" />{error}</span>}
                {/* Счётчик узлов и рёбер */}
                {graphData && !loading && (
                  <span className="text-xs text-slate-500 ml-auto">
                    {graphData.stats.total_nodes} узлов, {graphData.stats.total_edges} рёбер
                  </span>
                )}
              </div>

              {/* --- Контейнер Cytoscape --- */}
              {/* <div> куда Cytoscape рендерит <canvas> */}
              {/* Тёмный фон (#060a14) — самый тёмный элемент для контраста с графом */}
              <div ref={containerRef} className="flex-1 bg-[#060a14]" style={{ minHeight: 300 }} />

              {/* --- Легенда типов узлов --- */}
              {/* Показывает цвет и символ для каждого типа узла:
                    IP-адрес (◆ оранжевый), Хост (■ синий), Пользователь (▣ фиолетовый),
                    Процесс (⬡ красный), Файл (▲ зелёный), Домен (● жёлтый) */}
              <div className="flex items-center gap-4 px-4 py-2 border-t border-slate-700/30 bg-[#0d1220] text-[10px] text-slate-500 flex-wrap">
                {[
                  { type: 'IP-адрес', color: '#f97316', shape: '◆' },
                  { type: 'Хост', color: '#3b82f6', shape: '■' },
                  { type: 'Пользователь', color: '#8b5cf6', shape: '▣' },
                  { type: 'Процесс', color: '#ef4444', shape: '⬡' },
                  { type: 'Файл', color: '#22c55e', shape: '▲' },
                  { type: 'Домен', color: '#eab308', shape: '●' },
                ].map(l => (
                  <span key={l.type} className="flex items-center gap-1">
                    <span style={{ color: l.color }}>{l.shape}</span>{l.type}
                  </span>
                ))}
              </div>
            </div>

            {/* ============================================================== */}
            {/* ПРАВАЯ ПАНЕЛЬ — Детали, Журнал запросов, Статистика           */}
            {/* ============================================================== */}
            <div className="w-80 border-l border-slate-700/50 flex flex-col bg-[#0d1220] shrink-0">
              <ScrollArea className="h-full p-3 space-y-4">

                {/* --- Секция: Информация о выбранном алерте --- */}
                {/* Показывается, если selectedAlert !== null */}
                {/* Отображает: описание правила, rule_id, severity, агент, IP, пользователь, процесс */}
                {selectedAlert && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Eye className="w-4 h-4 text-amber-400" />
                      <span className="text-xs font-semibold text-slate-300">Выбранный алерт</span>
                    </div>
                    <div className="bg-[#111827] rounded-lg p-3 space-y-1.5 text-[11px]">
                      {/* Описание правила */}
                      <p className="text-slate-300 font-medium">{selectedAlert.rule_description}</p>
                      {/* Параметры алерта: rule_id, severity, агент, IP */}
                      <div className="grid grid-cols-2 gap-1 text-[10px] text-slate-500">
                        <span>Rule: {selectedAlert.rule_id}</span>
                        <span>Severity: <span className={severityColor(selectedAlert.severity) + ' text-white px-1 rounded text-[9px]'}>L{selectedAlert.severity}</span></span>
                        <span>Агент: {selectedAlert.agent_name}</span>
                        <span>IP: {selectedAlert.agent_ip}</span>
                        {selectedAlert.user_name && <span className="col-span-2">Пользователь: {selectedAlert.user_name}</span>}
                        {selectedAlert.src_ip && <span className="col-span-2">Src IP: {selectedAlert.src_ip}</span>}
                      </div>
                      {/* Процесс: имя + командная строка */}
                      {selectedAlert.process_name && (
                        <div className="mt-1.5">
                          <p className="text-slate-500 text-[9px] mb-0.5">Процесс:</p>
                          <p className="text-red-400 font-mono text-[10px] break-all">{selectedAlert.process_name}</p>
                          {selectedAlert.process_cmd && <p className="text-slate-500 font-mono text-[9px] break-all mt-0.5">{selectedAlert.process_cmd}</p>}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* --- Секция: Детали выбранного узла --- */}
                {/* Показывается, если selectedNode !== null */}
                {/* Отображает: тип узла (цветной квадрат), метку, IP, команду, путь */}
                {selectedNode && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      {/* Цветной индикатор типа узла */}
                      <div className="w-3 h-3 rounded" style={{ backgroundColor: selectedNode.data.color }} />
                      <span className="text-xs font-semibold text-slate-300">{selectedNode.data.typeLabel}</span>
                    </div>
                    <div className="bg-[#111827] rounded-lg p-3 space-y-1.5 text-[11px]">
                      {/* Метка узла (IP, hostname, username, и т.д.) */}
                      <p className="text-slate-200 font-mono font-medium">{selectedNode.data.label}</p>
                      {/* IP-адрес (для узлов типа ip/host) */}
                      {selectedNode.data.ip && <p className="text-[10px] text-slate-500">IP: {selectedNode.data.ip}</p>}
                      {/* Командная строка (для узлов типа process) */}
                      {selectedNode.data.command && <p className="text-[10px] text-red-400 font-mono break-all mt-1">{selectedNode.data.command}</p>}
                      {/* Полный путь (для узлов типа file) */}
                      {selectedNode.data.full_path && <p className="text-[10px] text-green-400 font-mono break-all mt-1">{selectedNode.data.full_path}</p>}
                    </div>
                  </div>
                )}

                {/* --- Секция: Детали выбранного ребра --- */}
                {/* Показывается, если selectedEdge !== null */}
                {/* Отображает: тип связи, source → target, rule_id, severity, full_log */}
                {selectedEdge && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      {/* Иконка стрелки с цветом ребра */}
                      <ChevronRight className="w-4 h-4" style={{ color: selectedEdge.data.color }} />
                      <span className="text-xs font-semibold text-slate-300">{selectedEdge.data.typeLabel}</span>
                    </div>
                    <div className="bg-[#111827] rounded-lg p-3 space-y-1.5 text-[11px]">
                      {/* Направление связи: source → target */}
                      {/* ID узлов содержат префикс типа (напр. "ip-10.0.0.1"), убираем его через split('-').slice(1) */}
                      <p className="text-slate-300">{selectedEdge.data.source.split('-').slice(1).join('-')} → {selectedEdge.data.target.split('-').slice(1).join('-')}</p>
                      {/* Rule ID и Severity */}
                      {selectedEdge.data.rule_id && <p className="text-[10px] text-slate-500">Rule: {selectedEdge.data.rule_id} | Severity: L{selectedEdge.data.severity}</p>}
                      {/* Полный лог события */}
                      {selectedEdge.data.full_log && <p className="text-[9px] text-slate-500 font-mono break-all mt-1">{selectedEdge.data.full_log}</p>}
                    </div>
                  </div>
                )}

                {/* --- Секция: Журнал запросов --- */}
                {/* Показывает 6 шагов алгоритма анализа с анимацией */}
                {/* Каждый шаг: номер, название, описание, количество результатов */}
                {/* activeStep контролирует, какие шаги «подсвечены» (синий) */}
                {graphData && graphData.query_log.length > 0 && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-cyan-400" />
                      {/* Счётчик: activeStep / totalSteps */}
                      <span className="text-xs font-semibold text-slate-300">Журнал запросов ({activeStep}/{graphData.query_log.length})</span>
                    </div>
                    <div className="space-y-1">
                      {graphData.query_log.map((q) => (
                        // Шаг запроса: подсвечен (cyan), если step <= activeStep
                        <div key={q.step} className={`flex items-start gap-2 px-2.5 py-1.5 rounded-md text-[10px] ${q.step <= activeStep ? 'bg-cyan-500/10 text-cyan-300' : 'bg-slate-800/50 text-slate-600'}`}>
                          <span className="font-mono font-bold w-4 shrink-0">{q.step}</span>
                          <div className="min-w-0">
                            <p className="font-medium">{q.name}</p>
                            <p className="text-slate-500 mt-0.5">{q.description}</p>
                            <p className="text-slate-600 mt-0.5">Результатов: {q.results_count}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* --- Секция: Статистика графа --- */}
                {/* Общее количество узлов/рёбер + разбивка по типам */}
                {graphData && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Activity className="w-4 h-4 text-emerald-400" />
                      <span className="text-xs font-semibold text-slate-300">Статистика</span>
                    </div>
                    {/* Карточки: всего узлов / всего рёбер */}
                    <div className="grid grid-cols-2 gap-2">
                      <div className="bg-[#111827] rounded-lg p-2.5 text-center">
                        <p className="text-lg font-bold text-slate-200">{graphData.stats.total_nodes}</p>
                        <p className="text-[9px] text-slate-500">Узлов</p>
                      </div>
                      <div className="bg-[#111827] rounded-lg p-2.5 text-center">
                        <p className="text-lg font-bold text-slate-200">{graphData.stats.total_edges}</p>
                        <p className="text-[9px] text-slate-500">Рёбер</p>
                      </div>
                    </div>
                    {/* Разбивка по типам узлов */}
                    <div className="space-y-1">
                      {Object.entries(graphData.stats.node_types).map(([t, c]) => (
                        <div key={t} className="flex items-center justify-between text-[10px] px-2">
                          <span className="text-slate-500">{t}</span>
                          <span className="text-slate-400 font-mono">{c}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </ScrollArea>
            </div>
          </div>
        )}
      </main>

      {/* ================================================================== */}
      {/* Подвал (Footer)                                                    */}
      {/* Версия приложения и технологический стек                            */}
      {/* ================================================================== */}
      <footer className="px-4 py-2 border-t border-slate-700/50 bg-[#0d1220] flex items-center justify-between text-[10px] text-slate-600">
        <span>Graph Attack Chain — Wazuh Integration</span>
        <a href = 'https://github.com/dm3tr-0/Graph-Attack-Chain'>https://github.com/dm3tr-0/Graph-Attack-Chain</a>
      </footer>
    </div>
  );
}
