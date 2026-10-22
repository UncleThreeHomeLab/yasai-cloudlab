SELECT json_agg(t ORDER BY t.name)::text
FROM (
    SELECT 'db:' || datname name, datacl::text acl FROM pg_database
    UNION ALL SELECT 'schema:' || nspname, nspacl::text FROM pg_namespace
    UNION ALL SELECT 'relation:' || oid::text, relacl::text FROM pg_class
    UNION ALL SELECT 'default:' || oid::text, defaclacl::text FROM pg_default_acl
) t;
