# Спецификация REST + WebSocket API (Backend <-> Frontend)

Базовый URL: /api/v1
Авторизация: Authorization: Bearer <access_token>

## 1. Аутентификация
- POST /auth/login -> {"access_token": "...", "token_type": "bearer", "role": "admin"} (+ Refresh в HttpOnly cookie)
- POST /auth/refresh -> Обновление Access токена

## 2. Инциденты (REST)
- GET /incidents?status=new&action=BLOCK&domain=openai&page=1&size=20 -> Лента инцидентов с фильтрацией
- GET /incidents/{id} -> Детали инцидента + массив склеенных raw_events (5 мин), detected_entities и policies_verdicts
- PATCH /incidents/{id}/status -> Смена статуса (in_progress, resolved, false_positive). Доступно: analyst, admin

## 3. Администрирование и Аудит
- GET /domains | POST /domains | PATCH /domains/{id} -> Управление LLM-доменами (admin)
- GET /users | POST /users -> Управление пользователями (admin)
- GET /audit?actor_id=...&from=... -> Журнал аудита (auditor, admin)

## 4. WebSocket Push (Реальное время)
URL: ws://<host>/api/v1/ws/incidents?token=<access_token>

Формат JSON-сообщения на фронт:
{
  "event": "INCIDENT_CREATED",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "client_ip": "10.20.30.45",
    "domain": "://openai.com",
    "window_start": "2026-11-23T14:05:10Z",
    "window_end": "2026-11-23T14:10:10Z",
    "status": "new",
    "final_action": "BLOCK",
    "entities_summary": ["PASSPORT", "INN"]
  }
}
