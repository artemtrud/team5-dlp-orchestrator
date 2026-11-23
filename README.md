#  оманда 5 Ч Backend / ќркестратор инцидентов (LLM DLP)

—ервис приЄма событий от DNS-перехватчика и Proxy/DLP, склейки их в инциденты (по ключу IP + домен + окно 5 мин), хранени€ маскированных ѕƒн в PostgreSQL и отдачи ленты на фронтенд по REST/WebSocket.

## Ѕыстрый старт (Docker)
1. —копируйте .env.example в .env:
   cp .env.example .env
2. «апустите инфраструктуру и сервисы:
   docker-compose up --build -d
3. јвтоматическа€ документаци€ OpenAPI (Swagger) доступна по адресу:
   http://localhost:8000/docs

## –аспределение модулей в команде
- docker-compose.yml, docs/, app/main.py Ч “имлид (»нфра, контракты, сборка)
- app/db/ и alembic/ Ч ћодели PostgreSQL, миграции и фильтр маскировани€ ѕƒн
- app/worker/ Ч Ўина событий Redis Streams и логика склейки 5-минутного окна
- app/core/ Ч JWT-аутентификаци€, матрица ролей (analyst / admin / auditor) и аудит
- app/api/ Ч REST-ручки и WebSocket-push дл€ фронтенда
