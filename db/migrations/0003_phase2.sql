-- Investigation, integrations, credential exposure, sharing and cost.
-- credential_exposures stores no password and no password hash.

create table if not exists agent_runs (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  role text not null,
  model text not null,
  tokens_in integer not null,
  tokens_out integer not null,
  cost_aud numeric not null,
  duration_ms integer not null,
  output_hash text not null,
  status text not null check (status in ('ok', 'failed', 'stopped')),
  created_at timestamptz not null default now()
);

create table if not exists tenant_budgets (
  tenant_id uuid primary key references tenants (id),
  tier text not null,
  monthly_aud numeric not null
);

create table if not exists integration_tokens (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  provider text not null,
  ciphertext text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, provider)
);

create table if not exists m365_cached_users (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  graph_id text not null,
  upn text not null
);

create table if not exists m365_cached_domains (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  domain text not null
);

create table if not exists credential_exposures (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  domain text not null,
  email_ciphertext text not null,
  email_hash text not null,
  breach_name text not null,
  breach_date date,
  data_classes text[] not null,
  finding_id uuid references findings (id),
  resolved_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists sharing_preferences (
  tenant_id uuid not null references tenants (id),
  category text not null,
  enabled boolean not null default false,
  primary key (tenant_id, category)
);

create table if not exists shared_items (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  finding_id uuid not null references findings (id),
  category text not null,
  sanitised jsonb not null,
  cultural boolean not null default false,
  approved_by uuid,
  approved_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists cost_ledger (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  category text not null,
  units numeric not null,
  aud numeric not null,
  at timestamptz not null default now()
);

create table if not exists product_events (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  name text not null check (name in ('finding_viewed', 'finding_actioned', 'finding_dismissed')),
  finding_id uuid,
  at timestamptz not null default now()
);

alter table agent_runs enable row level security;
alter table agent_runs force row level security;
drop policy if exists tenant_isolation on agent_runs;
create policy tenant_isolation on agent_runs
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table tenant_budgets enable row level security;
alter table tenant_budgets force row level security;
drop policy if exists tenant_isolation on tenant_budgets;
create policy tenant_isolation on tenant_budgets
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table integration_tokens enable row level security;
alter table integration_tokens force row level security;
drop policy if exists tenant_isolation on integration_tokens;
create policy tenant_isolation on integration_tokens
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table m365_cached_users enable row level security;
alter table m365_cached_users force row level security;
drop policy if exists tenant_isolation on m365_cached_users;
create policy tenant_isolation on m365_cached_users
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table m365_cached_domains enable row level security;
alter table m365_cached_domains force row level security;
drop policy if exists tenant_isolation on m365_cached_domains;
create policy tenant_isolation on m365_cached_domains
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table credential_exposures enable row level security;
alter table credential_exposures force row level security;
drop policy if exists tenant_isolation on credential_exposures;
create policy tenant_isolation on credential_exposures
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table sharing_preferences enable row level security;
alter table sharing_preferences force row level security;
drop policy if exists tenant_isolation on sharing_preferences;
create policy tenant_isolation on sharing_preferences
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table shared_items enable row level security;
alter table shared_items force row level security;
drop policy if exists tenant_isolation on shared_items;
create policy tenant_isolation on shared_items
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table cost_ledger enable row level security;
alter table cost_ledger force row level security;
drop policy if exists tenant_isolation on cost_ledger;
create policy tenant_isolation on cost_ledger
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table product_events enable row level security;
alter table product_events force row level security;
drop policy if exists tenant_isolation on product_events;
create policy tenant_isolation on product_events
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

grant select, insert, update, delete on
  agent_runs, tenant_budgets, integration_tokens, m365_cached_users, m365_cached_domains,
  credential_exposures, sharing_preferences, shared_items, cost_ledger, product_events
to cti_app;

revoke update, delete on audit_log from cti_app;
