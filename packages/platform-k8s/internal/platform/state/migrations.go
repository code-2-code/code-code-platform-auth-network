package state

import statepostgres "code-code.internal/platform-k8s/internal/platform/state/postgres"

// Migrations define the Postgres-owned platform product/domain state schema.
var Migrations = []statepostgres.Migration{
	{
		Version: 1,
		Name:    "platform_domain_json_state",
		SQL: `
create table if not exists platform_providers (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table if not exists platform_profiles (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table if not exists platform_credentials (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table if not exists platform_oauth_sessions (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table if not exists platform_models (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table if not exists platform_catalog_rows (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);`,
	},
	{
		Version: 2,
		Name:    "profile_resource_json_state",
		SQL: `
create table if not exists platform_mcp_servers (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table if not exists platform_skills (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table if not exists platform_rules (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);`,
	},
	{
		Version: 3,
		Name:    "domain_events_and_externalized_k8s_state",
		SQL: `
create table if not exists platform_sessions (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table if not exists platform_chats (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table if not exists platform_agent_session_actions (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table if not exists platform_domain_outbox (
	event_id text primary key,
	subject text not null,
	payload bytea not null,
	aggregate_type text not null,
	aggregate_id text not null,
	aggregate_version bigint not null,
	created_at timestamptz not null default now(),
	published_at timestamptz,
	attempts integer not null default 0,
	last_error text not null default ''
);
create index if not exists platform_domain_outbox_unpublished_idx on platform_domain_outbox (created_at, event_id) where published_at is null;

create table if not exists platform_domain_consumer_events (
	consumer_name text not null,
	event_id text not null,
	processed_at timestamptz not null default now(),
	primary key (consumer_name, event_id)
);`,
	},
	{
		Version: 4,
		Name:    "cli_runtime_version_and_image_state",
		SQL: `
	create table if not exists platform_cli_version_snapshots (
	id text primary key,
	payload jsonb not null,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);`,
	},
	{
		Version: 7,
		Name:    "hot_list_query_indexes",
		SQL: `
create index if not exists platform_chats_scope_updated_id_idx on platform_chats (
	((coalesce(payload->>'scope_id', 'default'))),
	updated_at desc,
	id desc
);

create index if not exists platform_agent_session_actions_namespace_id_idx on platform_agent_session_actions (
	((payload->'metadata'->>'namespace')),
	id
);
update platform_agent_session_actions
set payload = jsonb_set(
	payload,
	'{metadata,labels}',
	coalesce(payload->'metadata'->'labels', '{}'::jsonb)
		|| jsonb_build_object('agentsessionaction.code-code.internal/session-id', coalesce(payload->'spec'->'action'->>'session_id', payload->'spec'->'action'->>'sessionId')),
	true
)
where coalesce(payload->'spec'->'action'->>'session_id', payload->'spec'->'action'->>'sessionId') is not null
	and coalesce(payload->'metadata'->'labels', '{}'::jsonb)->>'agentsessionaction.code-code.internal/session-id' is null;
create index if not exists platform_agent_session_actions_session_id_label_idx on platform_agent_session_actions (
	((coalesce(payload->'metadata'->'labels', '{}'::jsonb)->>'agentsessionaction.code-code.internal/session-id')),
	id
);

analyze platform_chats;
analyze platform_agent_session_actions;`,
	},
	{
		Version: 9,
		Name:    "drop_cli_definition_legacy_table",
		SQL: `
drop table if exists platform_cli_definitions cascade;`,
	},
	{
		Version: 10,
		Name:    "drop_vendor_definition_legacy_table",
		SQL: `
drop table if exists platform_vendor_definitions cascade;`,
	},
	{
		Version: 11,
		Name:    "drop_agent_run_projection_table",
		SQL: `
drop table if exists platform_agent_runs cascade;`,
	},
	{
		Version: 12,
		Name:    "model_registry_proto_read_model",
		SQL: `
create extension if not exists pg_trgm;
drop table if exists platform_model_definitions cascade;

create table if not exists platform_model_registry_entries (
	namespace text not null,
	vendor_id text not null,
	model_id text not null,
	definition jsonb not null,
	source_ref_vendor_id text,
	source_ref_model_id text,
	badges jsonb not null default '[]'::jsonb,
	pricing jsonb,
	generation bigint not null default 1,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now(),
	primary key (namespace, vendor_id, model_id)
);

create table if not exists platform_model_registry_observations (
	namespace text not null,
	vendor_id text not null,
	model_id text not null,
	source_id text not null,
	is_direct boolean not null default false,
	kind text not null default 'preset',
	source_model_id text,
	definition jsonb,
	badges jsonb not null default '[]'::jsonb,
	pricing jsonb,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now(),
	primary key (namespace, vendor_id, model_id, source_id, is_direct),
	foreign key (namespace, vendor_id, model_id)
		references platform_model_registry_entries(namespace, vendor_id, model_id)
		on delete cascade
);

create table if not exists platform_model_registry_source_status (
	namespace text not null,
	source_id text not null,
	last_started_at timestamptz,
	last_finished_at timestamptz,
	last_success_at timestamptz,
	status text not null default 'unknown',
	collected_count integer not null default 0,
	error_message text not null default '',
	primary key (namespace, source_id)
);

create index if not exists platform_model_registry_entries_source_ref_idx
	on platform_model_registry_entries(namespace, source_ref_vendor_id, source_ref_model_id, vendor_id, model_id);
create index if not exists platform_model_registry_entries_model_query_trgm_idx
	on platform_model_registry_entries using gin (lower(model_id) gin_trgm_ops);
create index if not exists platform_model_registry_entries_badges_gin_idx
	on platform_model_registry_entries using gin (badges);
create index if not exists platform_model_registry_observations_source_idx
	on platform_model_registry_observations(namespace, source_id, vendor_id, model_id);

analyze platform_model_registry_entries;
analyze platform_model_registry_observations;`,
	},
	{
		Version: 13,
		Name:    "model_registry_observation_callable_identity_pk",
		SQL: `
update platform_model_registry_observations
set source_model_id = ''
where source_model_id is null;

alter table platform_model_registry_observations
	alter column source_model_id set default '';
alter table platform_model_registry_observations
	alter column source_model_id set not null;

alter table platform_model_registry_observations
	drop constraint if exists platform_model_registry_observations_pkey;
alter table platform_model_registry_observations
	add primary key (namespace, vendor_id, model_id, source_id, source_model_id, is_direct);

drop index if exists platform_model_registry_observations_source_idx;
create index if not exists platform_model_registry_observations_source_idx
	on platform_model_registry_observations(namespace, source_id, source_model_id, vendor_id, model_id);

analyze platform_model_registry_observations;`,
	},
	{
		Version: 14,
		Name:    "model_registry_alias_lookup_projection",
		SQL: `
create table if not exists platform_model_registry_aliases (
	namespace text not null,
	vendor_id text not null,
	model_id text not null,
	alias_kind text not null default 'ALIAS_KIND_UNSPECIFIED',
	alias_value text not null,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now(),
	primary key (namespace, vendor_id, model_id, alias_kind, alias_value),
	foreign key (namespace, vendor_id, model_id)
		references platform_model_registry_entries(namespace, vendor_id, model_id)
		on delete cascade
);

delete from platform_model_registry_aliases;
insert into platform_model_registry_aliases (
	namespace, vendor_id, model_id, alias_kind, alias_value, created_at, updated_at
)
select entries.namespace,
       entries.vendor_id,
       entries.model_id,
       coalesce(nullif(trim(alias ->> 'kind'), ''), 'ALIAS_KIND_UNSPECIFIED') as alias_kind,
       trim(alias ->> 'value') as alias_value,
       now(),
       now()
from platform_model_registry_entries entries
cross join lateral jsonb_array_elements(coalesce(entries.definition -> 'aliases', '[]'::jsonb)) alias
where trim(coalesce(alias ->> 'value', '')) <> ''
on conflict do nothing;

create index if not exists platform_model_registry_aliases_lookup_idx
	on platform_model_registry_aliases(namespace, alias_value, vendor_id, model_id);
create index if not exists platform_model_registry_aliases_vendor_lookup_idx
	on platform_model_registry_aliases(namespace, vendor_id, alias_value, model_id);

analyze platform_model_registry_aliases;`,
	},
	{
		Version: 15,
		Name:    "model_registry_query_path_indexes",
		SQL: `
create index if not exists platform_model_registry_entries_model_id_lookup_idx
	on platform_model_registry_entries(namespace, model_id, vendor_id);
create index if not exists platform_model_registry_entries_source_model_lookup_idx
	on platform_model_registry_entries(namespace, source_ref_model_id, vendor_id, model_id);
create index if not exists platform_model_registry_observations_source_filter_idx
	on platform_model_registry_observations(namespace, source_id, vendor_id, model_id);

analyze platform_model_registry_entries;
analyze platform_model_registry_observations;`,
	},
	{
		Version: 16,
		Name:    "model_cards_and_organizations",
		SQL: `
create table if not exists platform_model_cards (
	namespace text not null,
	vendor_id text not null,
	model_id text not null,
	schema_version text not null default 'v1',
	metadata_json jsonb,
	markdown_body text not null default '',
	source_type text not null default '',
	source_url text not null default '',
	review_status text not null default 'unreviewed',
	reviewer text not null default '',
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now(),
	primary key (namespace, vendor_id, model_id),
	foreign key (namespace, vendor_id, model_id)
		references platform_model_registry_entries(namespace, vendor_id, model_id)
		on delete cascade
);

create table if not exists platform_organizations (
	org_code text not null primary key,
	org_name text not null default '',
	org_roles jsonb not null default '[]'::jsonb,
	country text not null default '',
	website text not null default '',
	status text not null default '',
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

analyze platform_model_cards;
analyze platform_organizations;`,
	},
	{
		Version: 17,
		Name:    "credential_material_encrypted_values",
		SQL: `
	create table if not exists platform_credential_material_values (
	  namespace text not null,
	  credential_id text not null,
	  material_key text not null,
	  key_id text not null,
	  nonce bytea not null,
	  ciphertext bytea not null,
	  created_at timestamptz not null default now(),
	  updated_at timestamptz not null default now(),
	  primary key (namespace, credential_id, material_key)
	);

create index if not exists platform_credential_material_values_credential_idx
	on platform_credential_material_values(namespace, credential_id);

analyze platform_credential_material_values;`,
	},
}
