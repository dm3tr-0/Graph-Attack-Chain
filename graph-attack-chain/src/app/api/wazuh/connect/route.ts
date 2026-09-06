// ============================================================================
// /api/wazuh/connect — API-маршрут подключения к Wazuh Manager API
// ============================================================================
//
// Назначение:
//   Проксирует POST-запрос от фронтенда к Flask-бэкенду (/api/wazuh/connect).
//   Устанавливает соединение с Wazuh Manager API и Elasticsearch,
//   выполняя JWT-аутентификацию на стороне Flask.
//
// Паттерн:
//   Next.js API Route (App Router) → HTTP-прокси → Flask (порт 5001)
//   Фронтенд не обращается к Flask напрямую — все запросы идут через
//   Next.js API routes, что позволяет:
//     - Избежать CORS-проблем (same-origin запросы)
//     - Скрывать URL бэкенда от клиента
//     - Добавлять middleware (аутентификацию, логирование)
//
// Запрос (POST):
//   Body (JSON):
//     url       — URL Wazuh Manager API (напр. "https://192.168.1.50:55000")
//     username  — имя пользователя Wazuh API
//     password  — пароль пользователя Wazuh API
//     es_url    — URL Elasticsearch / Wazuh Indexer
//     es_user   — имя пользователя Elasticsearch
//     es_pass   — пароль Elasticsearch
//
// Ответ (JSON):
//   Успех: { version: "4.9.1", agents_count: 5, token: "..." }
//   Ошибка: { error: "описание ошибки" }
//
// Ошибки:
//   503 — Flask-бэкенд недоступен (сетевая ошибка)
// ============================================================================

import { NextRequest, NextResponse } from 'next/server';

// URL Flask-бэкенда; по умолчанию http://localhost:5001
// Можно переопределить через переменную окружения FLASK_URL
const FLASK = process.env.FLASK_URL || 'http://localhost:5001';

// POST-обработчик: проксирует тело запроса к Flask /api/wazuh/connect
export async function POST(req: NextRequest) {
  try {
    // Читаем JSON-тело запроса от фронтенда (URL + учётные данные)
    const body = await req.json();
    // Пересылаем запрос к Flask-бэкенду
    const resp = await fetch(`${FLASK}/api/wazuh/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    // Получаем ответ от Flask и пересылаем его фронтенду
    const data = await resp.json();
    // Возвращаем ответ с тем же HTTP-статусом (200, 401, 500, и т.д.)
    return NextResponse.json(data, { status: resp.status });
  } catch (e) {
    // Flask-бэкенд недоступен — возвращаем 503 Service Unavailable
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Backend unavailable' }, { status: 503 });
  }
}
