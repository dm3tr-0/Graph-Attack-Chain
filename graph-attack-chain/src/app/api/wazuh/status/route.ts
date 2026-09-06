// ============================================================================
// /api/wazuh/status — API-маршрут проверки статуса подключения к Wazuh
// ============================================================================
//
// Назначение:
//   Проксирует GET-запрос к Flask-бэкенду (/api/wazuh/status).
//   Проверяет, активно ли подключение к Wazuh Manager API
//   (валидность JWT-токена, доступность сервера).
//
// Паттерн:
//   Next.js API Route (App Router) → HTTP-прокси → Flask (порт 5001)
//
// Запрос (GET):
//   Без параметров.
//
// Ответ (JSON):
//   Подключено:   { connected: true, version: "4.9.1", agents_count: 5 }
//   Не подключено: { connected: false, message: "..." }
//   Бэкенд недоступен: { connected: false, message: "Backend unavailable" }
//
// Использование:
//   Фронтенд может вызывать этот эндпоинт при загрузке страницы
//   для проверки, нужно ли показывать экран подключения или рабочее пространство.
//
// Примечание:
//   В отличие от других маршрутов, при ошибке соединения с Flask
//   возвращается не 503, а { connected: false } — это позволяет
//   фронтенду корректно обработать недоступность бэкенда.
// ============================================================================

import { NextResponse } from 'next/server';

// URL Flask-бэкенда; по умолчанию http://localhost:5001
const FLASK = process.env.FLASK_URL || 'http://localhost:5001';

// GET-обработчик: проверяет статус подключения к Wazuh через Flask
export async function GET() {
  try {
    // Запрос к Flask /api/wazuh/status
    // cache: 'no-store' — статус может измениться в любой момент
    const resp = await fetch(`${FLASK}/api/wazuh/status`, { cache: 'no-store' });
    const data = await resp.json();
    return NextResponse.json(data, { status: resp.status });
  } catch {
    // Flask-бэкенд недоступен — возвращаем connected: false
    // (без HTTP-ошибки, чтобы фронтенд мог корректно обработать)
    return NextResponse.json({ connected: false, message: 'Backend unavailable' });
  }
}
