-- Core tenancy, intelligence and audit tables.
-- The migration role owns these objects. The API uses cti_app, which cannot bypass row level security.

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'cti_app') then
    create role cti_app login password 'cti_app' nosuperuser nobypassrls nocreatedb nocreaterole;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'cti_worker') then
    create role cti_worker nosuperuser nobypassrls nocreatedb nocreaterole;
  end if;
end $$;

create table if not exists tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  type text not null check (type in ('acco', 'land_council', 'ams', 'indigenous_corporation', 'other')),
  aliases text[] not null default '{}',
  created_at timestamptz not null default now()
);

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  created_at timestamptz not null default now()
);

create table if not exists memberships (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  user_id uuid not null references users(id),
  role text not null check (role in ('owner', 'member', 'credential_viewer', 'analyst')),
  unique (tenant_id, user_id)
);

create table if not exists verified_domains (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  domain text not null,
  status text not null check (status in ('pending', 'verified', 'lapsed')),
  token text not null,
  method text,
  verified_at timestamptz,
  txt_missing_since timestamptz,
  created_at timestamptz not null default now(),
  unique (tenant_id, domain)
);

create unique index if not exists verified_domain_owner
  on verified_domains (domain)
  where status = 'verified';

create table if not exists sources (
  id text primary key,
  name text not null,
  type text,
  licence text,
  commercial_use text,
  cost text,
  coverage text,
  tlp text,
  access_method text,
  status text not null,
  reviewed_by text,
  notes text,
  terms_url text,
  cron text
);

create table if not exists observations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references tenants(id),
  source_id text not null,
  collected_at timestamptz not null,
  licence text not null,
  tlp text not null,
  raw_key text not null,
  sha256 text not null,
  payload jsonb not null,
  extracted_domain text,
  unique (source_id, sha256)
);

create table if not exists stix_objects (
  id text primary key,
  tenant_id uuid references tenants(id),
  type text not null,
  confidence smallint check (confidence is null or (confidence between 0 and 100)),
  body jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists findings (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  kind text not null,
  title text not null,
  plain_english_summary text not null,
  confidence smallint not null check (confidence between 0 and 100),
  confidence_factors jsonb not null,
  status text not null check (status in ('open', 'acknowledged', 'dismissed', 'challenged', 'resolved')),
  provenance jsonb not null,
  stix_refs jsonb not null default '[]',
  cultural boolean not null default false,
  created_at timestamptz not null default now(),
  constraint findings_provenance_chk check (jsonb_typeof(provenance) = 'array' and jsonb_array_length(provenance) >= 1),
  constraint findings_factors_chk check (jsonb_typeof(confidence_factors) = 'array' and jsonb_array_length(confidence_factors) >= 1)
);

create table if not exists finding_evidence (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  finding_id uuid not null references findings(id),
  observation_id uuid references observations(id),
  label text not null,
  object_key text,
  collected_at timestamptz not null,
  source_id text not null,
  licence text not null,
  tlp text not null
);

create table if not exists finding_feedback (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  finding_id uuid not null references findings(id),
  actor_id uuid,
  kind text not null check (kind in ('dismiss', 'challenge', 'reopen', 'uphold', 'adjust', 'withdraw')),
  reason text,
  note text,
  created_at timestamptz not null default now()
);

create table if not exists actions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  finding_id uuid references findings(id),
  kind text not null,
  status text not null check (status in ('proposed', 'approved', 'executed', 'failed', 'cancelled')),
  preview jsonb not null,
  preview_hash text not null,
  approved_by uuid,
  approved_at timestamptz,
  executed_at timestamptz,
  failure text,
  created_at timestamptz not null default now()
);

create table if not exists consents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  scope text not null,
  grantor_name text not null,
  grantor_role text not null,
  ip text,
  granted_at timestamptz not null default now(),
  revoked_at timestamptz
);

create table if not exists audit_log (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid,
  actor_id uuid,
  action text not null,
  target_type text,
  target_id text,
  metadata jsonb,
  at timestamptz not null default now()
);

create or replace function forbid_audit_mutation() returns trigger
language plpgsql as $$
begin
  raise exception 'audit_log is append-only';
end $$;

drop trigger if exists audit_log_no_update on audit_log;
create trigger audit_log_no_update
  before update or delete on audit_log
  for each row execute function forbid_audit_mutation();

-- Row level security. FORCE applies to the table owner as well. Superusers still bypass it,
-- so the application role must not be a superuser and must not have BYPASSRLS.
do $$
declare
  t text;
begin
  foreach t in array array[
    'memberships', 'verified_domains', 'findings', 'finding_evidence', 'finding_feedback', 'actions', 'consents'
  ]
  loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format('drop policy if exists tenant_isolation on %I', t);
    execute format(
      'create policy tenant_isolation on %I using (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid) with check (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
      t
    );
  end loop;
end $$;

alter table observations enable row level security;
alter table observations force row level security;
drop policy if exists observations_read on observations;
drop policy if exists observations_write on observations;
drop policy if exists observations_update on observations;
create policy observations_read on observations for select
  using (tenant_id is null or tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
create policy observations_write on observations for insert
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
create policy observations_update on observations for update
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table stix_objects enable row level security;
alter table stix_objects force row level security;
drop policy if exists stix_read on stix_objects;
drop policy if exists stix_insert on stix_objects;
drop policy if exists stix_update on stix_objects;
create policy stix_read on stix_objects for select
  using (tenant_id is null or tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
create policy stix_insert on stix_objects for insert
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
create policy stix_update on stix_objects for update
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table audit_log enable row level security;
alter table audit_log force row level security;
drop policy if exists audit_select on audit_log;
drop policy if exists audit_insert on audit_log;
create policy audit_select on audit_log for select
  using (tenant_id is not null and tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
create policy audit_insert on audit_log for insert
  with check (tenant_id is null or tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

create or replace function insert_shared_stix(p_id text, p_type text, p_confidence smallint, p_body jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into stix_objects (id, tenant_id, type, confidence, body)
  values (p_id, null, p_type, p_confidence, p_body)
  on conflict (id) do update
    set type = excluded.type,
        confidence = excluded.confidence,
        body = excluded.body;
end $$;

revoke all on function insert_shared_stix(text, text, smallint, jsonb) from public;
grant execute on function insert_shared_stix(text, text, smallint, jsonb) to cti_worker;

grant usage on schema public to cti_app, cti_worker;
grant select, insert, update, delete on all tables in schema public to cti_app;
revoke update, delete on audit_log from cti_app;
grant select, insert on audit_log to cti_app;
