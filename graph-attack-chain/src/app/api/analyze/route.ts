// ============================================================================
// /api/analyze — API-маршрут анализа алерта (построение графа атаки)
// ============================================================================
//
// Назначение:
//   Проксирует POST-запрос от фронтенда к Flask-бэкенду (/api/analyze).
//   Запускает 6-шаговый алгоритм анализа алерта, который:
//     1. Ищет аутентификационные события (same user, same agent)
//     2. Ищет сетевые соединения (same src/dst IP)
//     3. Ищет связанные алерты (same rule, same IPs)
//     4. Ищет lateral movement (IP на других хостах)
//     5. Ищет события процессов (same agent, time window)
//     6. Ищет файловые операции (same agent, time window)
//   Результат: направленный граф атаки (узлы + рёбра + статистика + лог запросов)
//
// Паттерн:
//   Next.js API Route (App Router) → HTTP-прокси → Flask (порт 5001)
//   Flask вызывает WazuhClient методы, которые делают _search запросы к Elasticsearch
//
// Запрос (POST):
//   Body (JSON):
//     agent_id        — ID агента (напр. "001")
//     agent_name      — имя агента (hostname)
//     agent_ip        — IP-адрес агента
//     user_name       — имя пользователя из алерта
//     process_name    — имя процесса из алерта
//     process_cmd     — командная строка процесса
//     src_ip          — source IP из алерта
//     rule_id         — ID правила Wazuh
//     rule_description — описание правила
//     severity        — уровень серьёзности
//     category        — категория алерта (authentication, network, file, и т.д.)
//     full_log        — полный лог события
//     time_window_min — временное окно для поиска (в минутах, напр. 60)
//
// Ответ (JSON):
//   Успех: {
//     nodes: GraphNode[],       — узлы графа (IP, хосты, пользователи, процессы, файлы, домены)
//     edges: GraphEdge[],       — рёбра графа (аутентификация, сеть, процесс, файл, registry, DNS)
//     stats: {                  — статистика графа
//       total_nodes: number,
//       total_edges: number,
//       node_types: Record<string, number>,  — количество узлов по типам
//       edge_types: Record<string, number>,  — количество рёбер по типам
//     },
//     query_log: QueryLogEntry[], — журнал 6 шагов анализа
//   }
//   Ошибка: { error: "описание ошибки" }
//
// Ошибки:
//   503 — Flask-бэкенд недоступен (сетевая ошибка)
// ============================================================================

import { NextRequest, NextResponse } from 'next/server';

// URL Flask-бэкенда; по умолчанию http://localhost:5001
const FLASK = process.env.FLASK_URL || 'http://localhost:5001';

// POST-обработчик: проксирует тело запроса к Flask /api/analyze
export async function POST(req: NextRequest) {
  try {
    // Читаем JSON-тело запроса от фронтенда (данные алерта)
    const body = await req.json();
    // Пересылаем запрос к Flask-бэкенду для выполнения анализа
    const resp = await fetch(`${FLASK}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    // Получаем результат анализа (граф атаки) и пересылаем фронтенду
    const data = await resp.json();
    return NextResponse.json(data, { status: resp.status });
  } catch (e) {
    // Flask-бэкенд недоступен — возвращаем 503 Service Unavailable
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Backend unavailable' }, { status: 503 });
  }
}
