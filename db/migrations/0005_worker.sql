-- Background worker state and alert delivery records.
-- collector_runs holds no tenant data the app needs, so cti_app gets no grant.

create table if not exists collector_runs (
  key text primary key,
  last_attempt_at timestamptz,
  last_success_at timestamptz,
  last_error text,
  summary jsonb not null default '{}'::jsonb
);

-- One row per finding and member, so an alert is planned and sent once.
create table if not exists alert_deliveries (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  finding_id uuid not null references findings (id),
  user_id uuid not null references users (id),
  delivery text not null check (delivery in ('immediate', 'digest', 'none')),
  attempts smallint not null default 0,
  last_error text,
  message_id text,
  sent_at timestamptz,
  created_at timestamptz not null default now(),
  unique (finding_id, user_id)
);

create index if not exists alert_deliveries_pending_idx on alert_deliveries (delivery, created_at) where sent_at is null;
create index if not exists observations_source_collected_idx on observations (source_id, collected_at);

alter table alert_deliveries enable row level security;
alter table alert_deliveries force row level security;
drop policy if exists tenant_isolation on alert_deliveries;
create policy tenant_isolation on alert_deliveries
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

grant select on alert_deliveries to cti_app;
