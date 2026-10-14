-- Core tenancy, sources, intelligence and findings.
-- Row-level security is forced on every tenant-owned table.
-- cti_app has no BYPASSRLS. Local password is a development default only.

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'cti_app') then
    create role cti_app login password 'cti_app' nosuperuser nobypassrls nocreatedb nocreaterole;
  else
    alter role cti_app nosuperuser nobypassrls nocreatedb nocreaterole;
  end if;
end
$$;

do $$
begin
  execute format('grant connect on database %I to cti_app', current_database());
end
$$;

grant usage on schema public to cti_app;

create table if not exists tenants (
  id uuid primary key,
  name text not null,
  org_type text not null check (org_type in ('ACCO', 'Land Council', 'AMS', 'Indigenous corporation', 'other')),
  created_at timestamptz not null default now()
);

create table if not exists users (
  id uuid primary key,
  email text not null unique,
  created_at timestamptz not null default now()
);

create table if not exists memberships (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  user_id uuid not null references users (id),
  role text not null check (role in ('owner', 'member', 'credential_viewer', 'analyst')),
  created_at timestamptz not null default now(),
  unique (tenant_id, user_id)
);

create table if not exists verified_domains (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  domain text not null,
  status text not null check (status in ('pending', 'email_pending', 'verified', 'lapsed')),
  method text check (method in ('dns_txt', 'email')),
  verify_token text not null,
  email_token_hash text,
  verified_at timestamptz,
  txt_missing_since timestamptz,
  created_at timestamptz not null default now(),
  unique (tenant_id, domain)
);

create table if not exists sources (
  id text primary key,
  name text not null,
  type text not null,
  licence text not null,
  commercial_use text,
  cost text,
  coverage text,
  tlp text not null,
  access_method text,
  status text not null check (status in ('candidate', 'approved', 'rejected', 'blocked')),
  reviewed_by text,
  notes text,
  cron text,
  terms_url text
);

create table if not exists observations (
  id uuid primary key,
  tenant_id uuid references tenants (id),
  source_id text not null references sources (id),
  collected_at timestamptz not null,
  licence text not null,
  tlp text not null,
  raw_key text not null,
  sha256 text not null,
  extracted_domain text,
  payload jsonb not null,
  unique (source_id, sha256)
);

create table if not exists stix_objects (
  id text primary key,
  tenant_id uuid references tenants (id),
  type text not null,
  confidence smallint check (confidence is null or confidence between 0 and 100),
  body jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists findings (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  kind text not null check (kind in ('lookalike_domain', 'credential_exposure', 'exposed_service', 'ransomware_mention', 'phishing_campaign')),
  title text not null,
  plain_english_summary text not null,
  confidence smallint not null check (confidence between 0 and 100),
  status text not null check (status in ('open', 'acknowledged', 'dismissed', 'challenged', 'resolved')),
  confidence_factors jsonb not null,
  stix_refs jsonb not null default '[]',
  provenance jsonb not null,
  cultural boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint findings_provenance_nonempty check (jsonb_typeof(provenance) = 'array' and jsonb_array_length(provenance) >= 1),
  constraint findings_factors_nonempty check (jsonb_typeof(confidence_factors) = 'array' and jsonb_array_length(confidence_factors) >= 1)
);

create table if not exists finding_evidence (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  finding_id uuid not null references findings (id),
  label text not null,
  object_key text,
  url text,
  collected_at timestamptz not null,
  source_id text not null,
  licence text not null,
  tlp text not null
);

create table if not exists finding_feedback (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  finding_id uuid not null references findings (id),
  actor_id uuid,
  action text not null check (action in ('dismiss', 'challenge', 'reopen', 'acknowledge', 'resolve')),
  reason text,
  comment text,
  created_at timestamptz not null default now()
);

create table if not exists actions (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  finding_id uuid references findings (id),
  kind text not null,
  status text not null check (status in ('proposed', 'approved', 'executed', 'failed', 'cancelled')),
  preview jsonb not null,
  payload jsonb not null,
  proposed_by uuid,
  approved_by uuid,
  approved_at timestamptz,
  executed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists consents (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  scope text not null,
  grantor_name text not null,
  grantor_role text not null,
  ip text,
  granted_at timestamptz not null default now(),
  revoked_at timestamptz
);

create table if not exists audit_log (
  id uuid primary key,
  tenant_id uuid references tenants (id),
  actor_id uuid,
  action text not null,
  target_type text,
  target_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists findings_tenant_status_idx on findings (tenant_id, status);
create index if not exists stix_objects_tenant_idx on stix_objects (tenant_id);
create index if not exists observations_tenant_idx on observations (tenant_id);

create or replace function audit_log_immutable() returns trigger
language plpgsql as $$
begin
  raise exception 'audit_log is append-only';
end;
$$;

drop trigger if exists audit_log_no_mutation on audit_log;
create trigger audit_log_no_mutation
  before update or delete on audit_log
  for each row execute function audit_log_immutable();

alter table tenants enable row level security;
alter table tenants force row level security;
drop policy if exists tenant_isolation on tenants;
create policy tenant_isolation on tenants
  using (id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table memberships enable row level security;
alter table memberships force row level security;
drop policy if exists tenant_isolation on memberships;
create policy tenant_isolation on memberships
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table verified_domains enable row level security;
alter table verified_domains force row level security;
drop policy if exists tenant_isolation on verified_domains;
create policy tenant_isolation on verified_domains
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table observations enable row level security;
alter table observations force row level security;
drop policy if exists tenant_isolation on observations;
create policy tenant_isolation on observations
  using (
    tenant_id is null
    or tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
  )
  with check (
    (tenant_id is null and current_setting('app.actor_role', true) = 'collector')
    or tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
  );

alter table stix_objects enable row level security;
alter table stix_objects force row level security;
drop policy if exists tenant_isolation on stix_objects;
create policy tenant_isolation on stix_objects
  using (
    tenant_id is null
    or tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
  )
  with check (
    (tenant_id is null and current_setting('app.actor_role', true) = 'collector')
    or tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
  );

alter table findings enable row level security;
alter table findings force row level security;
drop policy if exists tenant_isolation on findings;
create policy tenant_isolation on findings
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table finding_evidence enable row level security;
alter table finding_evidence force row level security;
drop policy if exists tenant_isolation on finding_evidence;
create policy tenant_isolation on finding_evidence
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table finding_feedback enable row level security;
alter table finding_feedback force row level security;
drop policy if exists tenant_isolation on finding_feedback;
create policy tenant_isolation on finding_feedback
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table actions enable row level security;
alter table actions force row level security;
drop policy if exists tenant_isolation on actions;
create policy tenant_isolation on actions
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table consents enable row level security;
alter table consents force row level security;
drop policy if exists tenant_isolation on consents;
create policy tenant_isolation on consents
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table audit_log enable row level security;
alter table audit_log force row level security;
drop policy if exists tenant_isolation on audit_log;
create policy tenant_isolation on audit_log
  using (tenant_id is not distinct from nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id is not distinct from nullif(current_setting('app.tenant_id', true), '')::uuid);

grant select, insert, update, delete on tenants, users, memberships, verified_domains, observations, stix_objects, findings, finding_evidence, finding_feedback, actions, consents to cti_app;
grant select on sources to cti_app;
grant select, insert on audit_log to cti_app;
revoke update, delete on audit_log from cti_app;
