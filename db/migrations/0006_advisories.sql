-- Shared Australian-focused advisories and ransomware listings.
-- Public intelligence with no tenant data, so no row-level security;
-- cti_app may read, only the worker (table owner) writes.

create table if not exists advisories (
  id uuid primary key,
  source_id text not null references sources (id),
  external_id text not null unique,
  title text not null,
  url text not null,
  summary text not null,
  published_at timestamptz not null,
  cves text[] not null default '{}',
  tags text[] not null default '{}',
  attack_techniques text[] not null default '{}',
  licence text not null,
  tlp text not null default 'TLP:CLEAR',
  collected_at timestamptz not null default now()
);

create index if not exists advisories_published_idx on advisories (published_at desc);
create index if not exists advisories_tags_idx on advisories using gin (tags);

create table if not exists au_ransomware_victims (
  id uuid primary key,
  external_id text not null unique,
  victim text not null,
  website text,
  activity text,
  group_name text not null,
  discovered_at timestamptz not null,
  country text not null default 'AU',
  collected_at timestamptz not null default now()
);

create index if not exists au_ransomware_discovered_idx on au_ransomware_victims (discovered_at desc);

grant select on advisories, au_ransomware_victims to cti_app;
