# Развёртывание и эксплуатация

## Docker Compose и WSL

Для контейнерного запуска нужны Docker Engine, плагин Compose и доступ к
Docker Hub и индексу Python-пакетов при сборке. Образ приложения использует
Python 3.11 slim, БД — postgres:18.3-bookworm.
Dockerfile устанавливает проект и зависимости приложения из `pyproject.toml`
с constraints-runtime.txt. Инструменты разработки устанавливаются отдельно при разработке.

В Windows используйте Bash в WSL Ubuntu с доступным Docker Engine.
Docker Desktop для этого сценария не требуется. Проверьте `docker version`
и `docker compose version`. Перейдите в корень репозитория на /mnt/<диск>/...
или в его фактический каталог. Windows .venv для контейнеров не используется.
На смонтированной Windows-файловой системе chmod может зависеть от настроек
WSL. Секретный env-файл можно хранить в домашнем каталоге WSL с правами 0600
и передавать его через --env-file.

Основной сценарий показан в [README](../README.md). Для первого запуска создайте
новый env-файл из .env.example и задайте разные `POSTGRES_PASSWORD`,
`MIGRATOR_PASSWORD` и APP_PASSWORD. Имена БД и администратора выбирайте
из латинских букв, цифр и подчёркиваний. Пароль передаётся libpq через
`PGPASSWORD`, поэтому кодирование пароля в URL для Compose не требуется.
Одинарные кавычки в env-файле сохраняют буквальные $ и #. Саму одинарную
кавычку в значении нужно экранировать по синтаксису Compose env-файла.

```bash
dc() {
    docker compose -p sde-local --env-file .env "$@"
}
dc config --quiet
dc up -d --build --wait
dc ps -a
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/health/ready
```

Ожидаются healthy у db и api, Exited (0) у migrate.
Сначала Compose ждёт TCP-готовности PostgreSQL через pg_isready,
затем выполняет python -m alembic upgrade head.
После успешной миграции запускается Uvicorn. Миграция выполняется отдельным
сервисом. Повторный up может повторно запустить завершившийся migrate.

В контейнере Uvicorn слушает 0.0.0.0:8000, на хосте порт опубликован только
как 127.0.0.1:8000. PostgreSQL подключён к внутренней сети `backend`.
API также подключён к сети `frontend` для публикации порта.
Фактическая доступность из Windows зависит от режима сети WSL.
Сначала проверяйте localhost из WSL, затем из Windows. При проблеме
проверьте локальную маршрутизацию, сохраняя loopback-привязку API.

## Настройки

Compose читает .env или явно указанный --env-file.
Само приложение автоматически .env не загружает.

| Переменная Compose | Обязательность и значение | Назначение |
|---|---|---|
| `POSTGRES_USER` | По умолчанию `sde_admin` | Административная роль новой PostgreSQL. В .env.example задана явно |
| `POSTGRES_DB` | Обязательна, пример sde | База приложения |
| `POSTGRES_PASSWORD` | Обязательна | Пароль административной роли |
| `MIGRATOR_PASSWORD` | Обязательна | Пароль `sde_migrator` |
| `APP_PASSWORD` | Обязательна | Пароль `sde_runtime` |
| `COMPOSE_PROJECT_NAME` | Необязательна, также задаётся через -p | Пространство имён контейнеров, сетей, томов и тега образа |
| `SDE_MAX_REQUEST_BODY_BYTES` | По умолчанию 5242880 | Передаётся API как лимит тела |

Compose формирует `SDE_DATABASE_URL` отдельно для migrate и api с host=db.
Другие переменные `SDE_` из файла `.env` на хосте автоматически в API не передаются.

| Настройка приложения | По умолчанию | Назначение |
|---|---|---|
| `SDE_DATABASE_URL` | None, для запуска API и онлайн-миграций требуется | SQLAlchemy URL PostgreSQL |
| `SDE_MAX_REQUEST_BODY_BYTES` | 5242880, целое > 0 | Максимум полученных HTTP-байтов тела |
| `SDE_RULES_DIRECTORY` | rules рядом с config.py установленного пакета | Обычные правила и подкаталог correlation |
| `SDE_APP_NAME` | security-detection-engine | Поле настроек имени приложения |
| `SDE_VERSION` | 0.1.0 | Версия в /health |
| `SDE_LOG_LEVEL` | INFO | Поле настроек LogLevel, DEBUG/INFO/WARNING/ERROR. Конфигурацию логов Uvicorn само по себе не меняет |

`PGPASSWORD` — переменная клиента libpq, которую Compose задаёт соответствующим
паролем роли. Для внешней БД можно использовать pgpass. `SDE_TEST_DATABASE_URL`
используется только тестовыми фикстурами и описана в [development.md](development.md).

## Роли, схема и данные

Административная роль является суперпользователем и создаёт роли приложения.
Скрипт `deploy/roles.sh` выполняется при первичной инициализации нового кластера.
Он проверяет разные пароли, отзывает права PUBLIC на базу и схему public,
создаёт роли и настраивает привилегии по умолчанию.

| Роль | Права и назначение |
|---|---|
| `sde_admin` либо `POSTGRES_USER` | Инициализация кластера и операции администратора |
| `sde_migrator` | CONNECT, USAGE/CREATE в public, владелец таблиц приложения после миграций |
| `sde_runtime` | CONNECT, USAGE в public, SELECT/INSERT таблиц приложения, SELECT alembic_version |

Роль приложения не получает административные атрибуты, членство в других ролях,
TEMP, DDL, UPDATE, DELETE и TRUNCATE. В текущей схеме нет последовательностей.
Будущие таблицы, созданные `sde_migrator` в public, получают SELECT/INSERT для
sde_runtime. Для иных объектов права нужно определить при соответствующей миграции.

Миграции `0001_storage` и `0002_unique_events` создают таблицы и уникальность
события внутри корреляции. Ожидаемая приложением ревизия — 0002_unique_events.
Readiness проверяет ревизию и наличие четырёх таблиц. Детальная проверка ORM
выполняется отдельной командой.

```bash
dc run --rm --no-deps migrate python -m alembic check
```

Пароли из env-файла не меняют существующие роли автоматически.
Для существующего тома на `0001_storage` используйте
[переход на разделённые роли](../deploy/role-transition.md).
Эта процедура требует резервной копии и выполняется оператором явно.

Данные находятся в именованном томе `postgres_data` проекта Compose, смонтированном
в /var/lib/postgresql. `PGDATA` равен /var/lib/postgresql/18/docker.
При смене имени проекта Compose может подключить новый пустой том.
Сохраняйте имя проекта и защищённый env-файл при повторном запуске.

## Операции и диагностика

```bash
dc ps -a
dc logs --tail=100 api migrate db
dc restart api
dc stop
dc up -d --wait
```

stop останавливает контейнеры и сохраняет их вместе с данными.
down удаляет контейнеры и сети, именованный том сохраняется.
Добавление флага -v к down удаляет том с данными.
Такое удаление необратимо без резервной копии и не входит в обычную остановку.

При ошибке migrate проверьте код завершения и журналы, имя базы, пароль,
владельца таблиц и текущую ревизию. API ждёт успешного завершения миграции.
Конфликт уникальности при upgrade требует проверки существующих записей
оператором. Скрипты проекта автоматически такие записи не исправляют.

Liveness /health зависит от процесса API и возвращает status=ok и version.
Readiness /health/ready возвращает status=ready либо 503 при недоступной
или несовместимой схеме. При остановке PostgreSQL liveness остаётся доступной.
После восстановления БД новые запросы могут использовать пул соединений.
Потерянные запросы автоматически не повторяются.

Ошибка на занятом порту 8000 требует проверить, какое локальное приложение
его использует. Старый env-файл без новых паролей блокирует запуск Compose.
Просматривая логи, учитывайте возможное присутствие содержимого ошибок БД
на стороне сервера. Перед передачей диагностики удаляйте чувствительные данные.

## Локальный запуск с системной PostgreSQL

Пример для Windows PowerShell использует Python 3.11, PostgreSQL 18 и клиентские
утилиты PostgreSQL в `PATH`. Работайте из корня репозитория. Проверьте службу и
готовность сервера принимать соединения, затем подключитесь через `psql`.

```powershell
Get-Service -Name 'postgresql*'
pg_isready -h 127.0.0.1 -p 5432
psql -X -h 127.0.0.1 -p 5432 -U postgres -d postgres -v ON_ERROR_STOP=1
```

Продолжайте при состоянии службы `Running` и ответе `accepting connections`.
Используйте административную роль своего выделенного кластера для первоначальной
настройки. В сеансе `psql` убедитесь, что имя новой рабочей базы и имена обеих
ролей свободны. Оба запроса должны вернуть пустой результат. При совпадении
остановитесь и проверьте назначение существующих объектов.

```sql
SELECT datname FROM pg_database WHERE datname = 'sde_local';
SELECT rolname FROM pg_roles WHERE rolname IN ('sde_migrator', 'sde_runtime');
```

Создайте рабочую базу отдельно от тестовой. После подключения к ней проверьте
имя базы, сервер и пользователя через `\conninfo`. При ошибке остановите настройку.

```sql
CREATE DATABASE sde_local TEMPLATE template0;
\connect sde_local
\conninfo
```

После подключения к `sde_local` выполните команды ниже. Введите два разных случайных
пароля по запросам `\password`. Роли создаются без административных привилегий
и членства в других ролях. Владельцем базы остаётся администратор.

```sql
BEGIN;
CREATE ROLE sde_migrator LOGIN;
CREATE ROLE sde_runtime LOGIN;
\password sde_migrator
\password sde_runtime
REVOKE ALL ON DATABASE sde_local FROM PUBLIC;
GRANT CONNECT ON DATABASE sde_local TO sde_migrator, sde_runtime;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO sde_migrator;
GRANT USAGE ON SCHEMA public TO sde_runtime;
SET LOCAL ROLE sde_migrator;
CREATE TABLE public.alembic_version (version_num varchar(32) NOT NULL PRIMARY KEY);
GRANT SELECT ON public.alembic_version TO sde_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT ON TABLES TO sde_runtime;
COMMIT;
\q
```

Как и в `deploy/roles.sh`, таблицу версий создаёт `sde_migrator` **до** назначения
привилегий по умолчанию. Поэтому `sde_runtime` может только читать её. Таблицы,
которые затем создадут миграции, разрешают приложению чтение и вставку.

Вне репозитория подготовьте отдельный файл паролей libpq для текущего пользователя
и ограничьте доступ к нему средствами Windows. Пример пути и формата двух строк
приведён ниже. Впишите назначенные пароли вместо обозначений в угловых скобках.
В полях файла символы `:` и `\` экранируются обратной косой чертой. Сохраните файл
как обычный текст UTF-8 без BOM. Существующий `pgpass.conf` можно использовать,
если он уже содержит подходящие записи.

```text
127.0.0.1:5432:sde_local:sde_migrator:<пароль мигратора>
127.0.0.1:5432:sde_local:sde_runtime:<пароль приложения>
```

В новой сессии PowerShell без заданного `PGPASSWORD` укажите путь к подготовленному
файлу. Установите приложение и примените миграции от имени владельца таблиц.

```powershell
$env:PGPASSFILE = Join-Path $env:APPDATA 'postgresql/sde-local.pgpass'
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c constraints-runtime.txt .
$env:SDE_DATABASE_URL = 'postgresql+psycopg://sde_migrator@127.0.0.1:5432/sde_local'
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic check
```

После успешного обновления до `0002_unique_events` и проверки схемы запустите
API с правами приложения в той же сессии.

```powershell
$env:SDE_DATABASE_URL = 'postgresql+psycopg://sde_runtime@127.0.0.1:5432/sde_local'
.\.venv\Scripts\python.exe -m uvicorn security_detection_engine.api.app:app --host 127.0.0.1 --port 8000
```

В другом окне PowerShell проверьте процесс и готовность базы. Ожидаются
`status=ok` с версией `0.1.0` и `status=ready` соответственно.

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/health/ready
```

В Linux используйте те же SQL-команды, `python3.11 -m venv .venv` и
`.venv/bin/python`. Переменные окружения задаются через `export`, а файл
паролей должен быть доступен только владельцу (режим `0600`).
