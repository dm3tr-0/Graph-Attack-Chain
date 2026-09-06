// ============================================================================
// /api/wazuh/alerts — API-маршрут получения алертов Wazuh
// ============================================================================
//
// Назначение:
//   Проксирует GET-запрос от фронтенда к Flask-бэкенду (/api/wazuh/alerts).
//   Возвращает список алертов (событий безопасности) для указанного агента
//   с фильтрацией по серьёзности и временному окну.
//
// Паттерн:
//   Next.js API Route (App Router) → HTTP-прокси → Flask (порт 5001)
//   Flask выполняет _search запрос к Elasticsearch (wazuh-alerts-* индекс)
//
// Запрос (GET):
//   Query-параметры:
//     agent_id     — ID агента Wazuh (напр. "001") — обязательный
//     limit        — максимальное количество алертов (по умолчанию 50)
//     severity_min — минимальный уровень серьёзности (по умолчанию 0)
//                    Шкала Wazuh: 0-3 (низкий), 4-6 (средний), 7-9 (высокий), 10+ (критический)
//     hours        — временное окно в часах (по умолчанию 24)
//
// Ответ (JSON):
//   Успех: { alerts: [{ event_id, timestamp, rule_id, rule_description, severity, ... }], total: 150 }
//   Ошибка: { error: "описание ошибки" }
//
// Примечание:
//   Flask конвертирует эти параметры в Elasticsearch _search запрос
//   с range-фильтром по timestamp и term-фильтром по agent.id.
// ============================================================================

import { NextRequest, NextResponse } from 'next/server';

// URL Flask-бэкенда; по умолчанию http://localhost:5001
const FLASK = process.env.FLASK_URL || 'http://localhost:5001';

// GET-обработчик: проксирует запрос к Flask /api/wazuh/alerts?...
export async function GET(req: NextRequest) {
  // Разбор query-параметров из URL запроса
  const sp = req.nextUrl.searchParams;
  const agentId = sp.get('agent_id');            // ID агента (обязательный)
  const limit = sp.get('limit') || '50';         // Максимум алертов (по умолчанию 50)
  const severityMin = sp.get('severity_min') || '0'; // Минимальный severity (по умолчанию 0)
  const hours = sp.get('hours') || '24';         // Временное окно в часах (по умолчанию 24)

  // Формирование query-параметров для запроса к Flask
  const params = new URLSearchParams({
    agent_id: agentId || '',
    limit,
    severity_min: severityMin,
    hours,
  });

  try {
    // Запрос к Flask-бэкенду с параметрами фильтрации
    // cache: 'no-store' — всегда свежие алерты (могут поступать в реальном времени)
    const resp = await fetch(`${FLASK}/api/wazuh/alerts?${params}`, { cache: 'no-store' });
    const data = await resp.json();
    return NextResponse.json(data, { status: resp.status });
  } catch (e) {
    // Flask-бэкенд недоступен
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Backend unavailable' }, { status: 503 });
  }
}
