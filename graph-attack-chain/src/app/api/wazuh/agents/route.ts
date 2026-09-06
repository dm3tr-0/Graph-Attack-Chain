// ============================================================================
// /api/wazuh/agents — API-маршрут получения списка агентов Wazuh
// ============================================================================
//
// Назначение:
//   Проксирует GET-запрос от фронтенда к Flask-бэкенду (/api/wazuh/agents).
//   Возвращает список зарегистрированных агентов (endpoint-ов) Wazuh Manager.
//
// Паттерн:
//   Next.js API Route (App Router) → HTTP-прокси → Flask (порт 5001)
//
// Запрос (GET):
//   Query-параметры:
//     status — фильтр по статусу агента (по умолчанию "active")
//              Возможные значения: "active", "disconnected", "never_connected", "all"
//
// Ответ (JSON):
//   Успех: { agents: [{ id, name, ip, status, os, ... }, ...] }
//   Ошибка: { error: "описание ошибки" }
//
// Примечание:
//   cache: 'no-store' — отключает кэширование Next.js, чтобы всегда
//   получать свежий список агентов от Wazuh API.
// ============================================================================

import { NextRequest, NextResponse } from 'next/server';

// URL Flask-бэкенда; по умолчанию http://localhost:5001
const FLASK = process.env.FLASK_URL || 'http://localhost:5001';

// GET-обработчик: проксирует запрос к Flask /api/wazuh/agents?status=...
export async function GET(req: NextRequest) {
  // Извлекаем параметр status из query-строки (по умолчанию "active")
  const status = req.nextUrl.searchParams.get('status') || 'active';
  try {
    // Запрос к Flask-бэкенду с параметром status
    // cache: 'no-store' — всегда свежие данные (агенты могут подключаться/отключаться)
    const resp = await fetch(`${FLASK}/api/wazuh/agents?status=${status}`, { cache: 'no-store' });
    const data = await resp.json();
    return NextResponse.json(data, { status: resp.status });
  } catch (e) {
    // Flask-бэкенд недоступен
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Backend unavailable' }, { status: 503 });
  }
}
