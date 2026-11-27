# Разработка, тестирование и измерения

## Окружение и исходники

Поддерживается Python >=3.11,<3.12. Версия проекта в `pyproject.toml`,
config.py и __init__.py — 0.1.0. Команды выполняются из корня репозитория.

В Linux с установленным Python 3.11 выполните следующие команды.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -c constraints-runtime.txt -e ".[dev]"
```

В Windows PowerShell можно использовать эти команды.

```powershell
py -3.11 -m venv .venv
.venv/Scripts/python.exe -m pip install -c constraints-runtime.txt -e ".[dev]"
.venv/Scripts/python.exe -m pytest -m "not postgresql"
```

Linux-контейнеры используют свой Python и установленные пакеты.
Windows .venv не подходит для выполнения внутри Linux.

Код расположен в src/security_detection_engine, правила входят в пакет.
Тесты находятся в tests, миграции в migrations. Pytest добавляет src
в pythonpath через pyproject.toml. Идентификаторы в коде английские,
комментарии и docstrings русские. Ruff использует line-length=88 и py311,
проверки E, F, I, UP. Для временных файлов тесты используют tmp_path.

## Проверки изменений

```bash
python -m pytest -m "not postgresql" -q
python -m ruff check .
python -m ruff format --check .
git diff --check
```

Этот запуск исключает PostgreSQL-тесты. Обычный pytest без
`SDE_TEST_DATABASE_URL` пропускает их с объяснением.
Для полного прогона нужна выделенная PostgreSQL с защитными условиями ниже.
При заданном URL ошибка подключения или несоответствие защиты вызывает провал,
фикстура не подменяет PostgreSQL SQLite.

После изменения модуля сначала выполняются его тесты, затем полный прогон.
Изменения ORM проверяются новой миграцией и alembic check.
Применённые миграции сохраняют свои идентификаторы независимо от текущего кода.
test_expected_revision_matches_alembic_head проверяет EXPECTED_REVISION
из storage/revision.py по фактическому графу Alembic.

## Подготовка PostgreSQL-тестов

Фикстура создаёт уникальную временную схему, применяет миграции и удаляет её
после теста. Ей требуется выделенная роль владельца выделенной тестовой базы.
База должна иметь комментарий sde:disposable-tests.
Роль должна быть без SUPERUSER, CREATEDB, CREATEROLE, REPLICATION, BYPASSRLS,
без членства в других ролях и без CONNECT к любой другой доступной базе.
Проверяются не только имя базы, но и эти условия перед выполнением DDL.

Команды ниже выполняются из корня репозитория в Bash (Linux или WSL).
Используйте отдельный Compose-проект `sde-tests` со своим томом. Для первого
запуска проверьте, что это имя свободно и том `sde-tests_postgres_data` ещё
не существует. При повторном запуске используйте тот же проект и файл паролей.

```bash
umask 077
cp -n .env.example .env.test
```

При первом запуске укажите в `.env.test` значения `POSTGRES_DB=sde`,
`POSTGRES_USER=sde_admin` и три разных случайных пароля для `POSTGRES_PASSWORD`,
`MIGRATOR_PASSWORD`, `APP_PASSWORD`. Запускайте из оболочки без одноимённых
переменных окружения, которые могли бы переопределить файл.

```bash
dc_test() { docker compose -p sde-tests --env-file .env.test "$@"; }
dc_test config --quiet
dc_test up -d --wait db
```

Один раз в новом кластере откройте сеанс администратора.

```bash
dc_test exec db psql -X -U sde_admin -d sde -v ON_ERROR_STOP=1
```

Введите отдельный пароль владельца тестовой базы по запросу `\password`.
Владелец получает право создавать изолированные схемы. Отзыв `CONNECT`
у `PUBLIC` ниже относится только к этому выделенному кластеру. Сценарий
инициализации Compose уже закрыл доступ `PUBLIC` к базе `sde`.

```sql
CREATE ROLE sde_test_owner LOGIN;
\password sde_test_owner
CREATE DATABASE sde_regression OWNER sde_test_owner;
COMMENT ON DATABASE sde_regression IS 'sde:disposable-tests';
REVOKE CONNECT ON DATABASE postgres, template1 FROM PUBLIC;
\q
```

Соберите отдельный образ для тестов из корня репозитория. Сборке нужен доступ
к реестру образов и индексу пакетов. Зависимости разработки устанавливаются
до подключения контейнера к изолированной сети БД.

```bash
docker build -t sde-tests-dev:local -f - . <<'DOCKERFILE'
FROM python:3.11-slim
WORKDIR /build
COPY pyproject.toml constraints-runtime.txt ./
COPY src/ src/
RUN python -m pip install --no-cache-dir -c constraints-runtime.txt ".[dev]"
DOCKERFILE
```

Введите пароль `sde_test_owner`. Контейнер получит его через окружение, а
`db` разрешится в адрес тестовой PostgreSQL внутри сети `sde-tests_backend`.
Исходники и тесты подключаются из текущего каталога только для чтения.

```bash
(
  read -rsp 'Пароль sde_test_owner: ' PGPASSWORD && echo
  export PGPASSWORD
  docker run --rm --network sde-tests_backend -e PGPASSWORD \
    -e SDE_TEST_DATABASE_URL=postgresql+psycopg://sde_test_owner@db:5432/sde_regression \
    --mount "type=bind,src=$PWD,dst=/checks,readonly" -w /checks \
    sde-tests-dev:local python -m pytest -q -rs -o cache_dir=/tmp/pytest-cache
)
```

Фикстура проверяет базу и права роли перед созданием схемы, затем задаёт
`SDE_DATABASE_URL` для API и Alembic. Проверьте итоговую строку pytest и
причины возможных пропусков. Остановите кластер с сохранением тома.

```bash
dc_test stop
```

## Миграции и зависимости

Основной путь создания схемы — Alembic. Для проверки модели используйте
migrate-сервис либо `SDE_DATABASE_URL` роли `sde_migrator` во внешней выделенной БД.

```bash
python -m alembic upgrade head
python -m alembic check
```

Downgrade/upgrade проверяется только в одноразовой схеме или базе.
Downgrade до base удаляет таблицы и их данные.

`pyproject.toml` описывает зависимости проекта и dev-набор.
`constraints-runtime.txt` фиксирует 25 пакетов приложения, проверенных в Linux-образе.
Файл позволяет установить согласованные версии без нового менеджера пакетов.
В Docker он применяется при установке runtime-зависимостей.
Зависимости разработки, система сборки, базовый образ и хеши артефактов этим файлом
полностью не фиксируются.

Для действующего контейнера можно проверить согласованность зависимостей.

```bash
docker compose -p sde-local --env-file .env exec -T api python -m pip check
docker compose -p sde-local --env-file .env exec -T api python -m pip list --format=freeze
```

Сверяйте установленный состав с constraints, отдельно учитывая локальный
проект, pip, setuptools и wheel.
Установку инструментов аудита выполняют в отдельном временном окружении.

## Подтверждённые результаты

При проверке документации 27 ноября 2026 года полный прогон с реальной
PostgreSQL завершился результатом 318 passed, 0 skipped, 1 warning за 27,94 с.
Ruff check, format и git diff --check прошли.
Проверены прямой Pipeline и приём событий всех источников через HTTP, партии из нескольких источников,
конфликт UUID при одновременной записи, откат отдельной транзакции, чтение до её фиксации,
миграции и восстановление API после недоступности PostgreSQL.
Количество тестов не является измерением покрытия кода.

Известное предупреждение Starlette связано с использованием HTTPX в
FastAPI TestClient. Оно не подавляется. При pip check в контейнере с файловой системой только для чтения
возможно предупреждение о недоступном кеше `pip`.

## Измерения производительности

Измерения выполнены 26 ноября 2026 года в WSL Ubuntu, Linux-контейнерах, Python 3.11.18,
PostgreSQL 18.3, с 8 доступными CPU и около 3,76 GiB RAM.
Использовались синтетические события, одно правило обнаружения и одно правило корреляции.
Для коротких проверок выполнено три измерения, приведены медианы.

| Pipeline, событий | Время | Событий/с | Пик выделенной памяти Python |
|---:|---:|---:|---:|
| 100 | 3,66 мс | 27 308 | 0,13 MiB |
| 1000 | 37,94 мс | 26 361 | 1,28 MiB |
| 10 000 | 332,37 мс | 30 087 | 12,57 MiB |

Память измерена отдельно через `tracemalloc` после создания входной партии.
RSS процесса и память контейнера не измерялись. Показатели Pipeline
относятся к анализу в памяти.

| REST API, событий | Размер тела | Полное время запроса |
|---:|---:|---:|
| 1 | 272 байта | 13,19 мс |
| 100 | 26 037 байт | 201,35 мс |
| 1000 | 260 262 байта | 1,528 с |

HTTP-время включает валидацию, Pipeline и фиксацию транзакции в PostgreSQL.

| Клиентов по 100 событий | Время завершения группы | Медиана запроса |
|---:|---:|---:|
| 2 | 312,80 мс | 299,59 мс |
| 5 | 2,620 с | 2,486 с |

При пяти клиентах задержка заметно возрастает. Причина снижения
производительности в этом измерении не установлена.

| Анализатор, 10 000 записей | Размер файла | Время |
|---|---:|---:|
| SSH | 890 000 байт | 426,19 мс |
| Windows XML | 1 280 017 байт | 454,79 мс |
| PCAP | 560 024 байта | 2,809 с |

Объёмы ограничивались 10 000 записями на источник.
Эти результаты описывают конкретное окружение и набор данных.
Промышленный SLA и предел устойчивой конкурентной нагрузки не определялись.
