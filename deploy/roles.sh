#!/bin/bash
# Официальный entrypoint может source-ить этот файл.
(
set -euo pipefail
: "${POSTGRES_PASSWORD:?}" "${MIGRATOR_PASSWORD:?}" "${APP_PASSWORD:?}"
if [[ "$MIGRATOR_PASSWORD" == "$APP_PASSWORD" || "$POSTGRES_PASSWORD" == "$APP_PASSWORD" || "$POSTGRES_PASSWORD" == "$MIGRATOR_PASSWORD" ]]; then
    echo 'Требуются три разных пароля.' >&2
    exit 1
fi
psql -X --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
BEGIN;
SET LOCAL log_statement = 'none';
SET LOCAL log_min_error_statement = 'panic';
\getenv migrator_password MIGRATOR_PASSWORD
\getenv app_password APP_PASSWORD
SELECT current_database() AS db \gset
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname IN ('sde_runtime','sde_migrator')) THEN
        RAISE EXCEPTION 'Application roles already exist; inspect cluster before transition';
    END IF;
    IF to_regclass('public.alembic_version') IS NOT NULL THEN
        IF (SELECT array_agg(version_num) FROM public.alembic_version)
                IS DISTINCT FROM ARRAY['0001_storage']::varchar[] THEN
            RAISE EXCEPTION 'Unexpected legacy revision';
        END IF;
        IF EXISTS (SELECT FROM public.correlation_events GROUP BY correlation_id,event_id
                   HAVING count(*) > 1) THEN
            RAISE EXCEPTION 'Duplicate correlation links; operator review required';
        END IF;
    ELSIF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public') THEN
        RAISE EXCEPTION 'Unexpected unversioned schema';
    END IF;
END $$;
CREATE ROLE sde_migrator LOGIN PASSWORD :'migrator_password';
CREATE ROLE sde_runtime LOGIN PASSWORD :'app_password';
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO sde_runtime, sde_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO sde_migrator;
GRANT USAGE ON SCHEMA public TO sde_runtime;
DO $$
DECLARE obj text;
BEGIN
    FOREACH obj IN ARRAY ARRAY['security_events','detection_alerts','correlation_alerts','correlation_events','alembic_version'] LOOP
        IF to_regclass(format('public.%I',obj)) IS NOT NULL THEN
            EXECUTE format('ALTER TABLE public.%I OWNER TO sde_migrator',obj);
            EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',obj);
            EXECUTE format('GRANT SELECT ON public.%I TO sde_runtime',obj);
            IF obj <> 'alembic_version' THEN
                EXECUTE format('GRANT INSERT ON public.%I TO sde_runtime',obj);
            END IF;
        END IF;
    END LOOP;
END $$;
SET LOCAL ROLE sde_migrator;
CREATE TABLE IF NOT EXISTS public.alembic_version (
    version_num varchar(32) NOT NULL PRIMARY KEY
);
GRANT SELECT ON public.alembic_version TO sde_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT ON TABLES TO sde_runtime;
COMMIT;
SQL
)
