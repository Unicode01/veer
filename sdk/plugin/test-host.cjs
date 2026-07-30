'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const vm = require('node:vm');
const API_CONTRACT = require('./api-contract.json');

const CONTROL_CAPABILITIES = Array.isArray(API_CONTRACT.control && API_CONTRACT.control.capabilities)
  ? API_CONTRACT.control.capabilities
  : [];
const CONTROL_CAPABILITY_BY_METHOD = new Map();
for (const capability of CONTROL_CAPABILITIES) {
  if (!capability || typeof capability.method !== 'string' || !capability.method) {
    throw new Error('plugin API contract contains an invalid control capability');
  }
  if (CONTROL_CAPABILITY_BY_METHOD.has(capability.method)) {
    throw new Error(`plugin API contract contains duplicate capability ${capability.method}`);
  }
  if (!Array.isArray(capability.phases) || capability.phases.length === 0 ||
      !Array.isArray(capability.contexts) || capability.contexts.length === 0) {
    throw new Error(`plugin API capability ${capability.method} has no execution scope`);
  }
  CONTROL_CAPABILITY_BY_METHOD.set(capability.method, capability);
}
if (!Array.isArray(API_CONTRACT.control_methods) ||
    API_CONTRACT.control_methods.length !== CONTROL_CAPABILITY_BY_METHOD.size ||
    API_CONTRACT.control_methods.some((method) => !CONTROL_CAPABILITY_BY_METHOD.has(method))) {
  throw new Error('plugin API contract capability list differs from control_methods');
}

const DEFAULT_TIMEOUT_MS = 20000;
const MAX_SCRIPT_BYTES = 1 << 20;
const MAX_MODULE_BYTES = 256 << 10;
const MAX_MODULE_COUNT = 128;
const MAX_MODULE_TOTAL_BYTES = 8 << 20;
const REGISTRATION_PERMISSIONS = new Set(['plugin.register', 'ebpf.load', 'event', 'hook.attach', 'ui']);
const RESERVED_EBPF_MAPS = new Set([
  'tc_prog_chain_v4', 'tc_plugin_config_v4', 'tc_plugin_interfaces_v4',
  'tc_dispatch_scratch_v4', 'tc_dispatch_scratch_v6', 'tc_plugin_ctx_v4',
  'tc_plugin_ctx_v6', 'tc_plugin_metrics', 'tc_packet_meta_bindings_v1',
  'tc_packet_meta_generation_v4', 'tc_packet_meta_generation_v6',
  'tc_packet_meta_v4', 'tc_packet_meta_v6', 'xdp_prog_chain',
]);

function cloneJSON(value) {
  if (value === undefined) return undefined;
  return JSON.parse(JSON.stringify(value));
}

function canonicalJSON(value) {
  const normalize = (item) => {
    if (Array.isArray(item)) return item.map(normalize);
    if (item && typeof item === 'object' && Object.prototype.toString.call(item) === '[object Object]') {
      return Object.fromEntries(Object.keys(item).sort().map((key) => [key, normalize(item[key])]));
    }
    return item;
  };
  return JSON.stringify(normalize(value)).replace(/[<>&\u2028\u2029]/g, (character) => ({
    '<': '\\u003c', '>': '\\u003e', '&': '\\u0026', '\u2028': '\\u2028', '\u2029': '\\u2029',
  })[character]);
}

function normalizeSchemaContract(item, prefix = '') {
  const stem = prefix ? `${prefix}_schema` : 'schema';
  const versionField = `${stem}_version`;
  const digestField = `${stem}_digest`;
  const maxVersion = Number(API_CONTRACT.schemas && API_CONTRACT.schemas.max_version || 1000000);
  const maxBytes = Number(API_CONTRACT.schemas && API_CONTRACT.schemas.max_bytes || (64 << 10));
  const version = Number(item[versionField] == null ? 1 : item[versionField]);
  if (!Number.isInteger(version) || version < 1 || version > maxVersion) throw new Error(`${versionField} is invalid`);
  item[versionField] = version;
  const schema = item[stem];
  if (schema == null) {
    delete item[stem];
    delete item[digestField];
    return;
  }
  if (typeof schema !== 'object' || Array.isArray(schema) || Object.prototype.toString.call(schema) !== '[object Object]') {
    throw new Error(`${stem} must be a JSON object`);
  }
  const canonical = canonicalJSON(schema);
  if (Buffer.byteLength(canonical, 'utf8') > maxBytes) throw new Error(`${stem} exceeds ${maxBytes} bytes`);
  item[stem] = JSON.parse(canonical);
  item[digestField] = crypto.createHash('sha256').update(canonical).digest('hex');
}

function eventSchemaVersion(value, label) {
  const maxVersion = Number(API_CONTRACT.schemas && API_CONTRACT.schemas.max_version || 1000000);
  const version = Number(value == null ? 1 : value);
  if (!Number.isInteger(version) || version < 1 || version > maxVersion) throw new Error(`${label} schema_version is invalid`);
  return version;
}

function nowISO() {
  return new Date().toISOString();
}

function token(value, label) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_.-]{0,63}$/.test(normalized)) {
    throw new Error(`${label} is invalid`);
  }
  return normalized;
}

function handlerName(value, label) {
  const normalized = String(value || '').trim();
  if (!/^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/.test(normalized)) {
    throw new Error(`${label} is invalid`);
  }
  return normalized;
}

function eventTopic(value, label) {
  const normalized = String(value || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  const parts = normalized.split('.');
  if (!normalized || normalized.length > 128 || parts.some((part) => !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(part))) {
    throw new Error(`${label} is invalid`);
  }
  return normalized;
}

function customEventSource(topic) {
  if (topic === 'plugin.lifecycle') return '';
  const parts = topic.split('.');
  return parts.length >= 2 && parts[0] === 'plugin' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(parts[1]) ? parts[1] : '';
}

function eventTopicWithinPrefix(topic, prefix) {
  return topic === prefix || topic.startsWith(`${prefix}.`);
}

function normalizeEventAccess(manifest, permissions) {
  const values = manifest.control && manifest.control.event_access;
  if (values == null) return [];
  if (!Array.isArray(values) || values.length > 64) throw new Error('control.event_access must be an array with at most 64 entries');
  if (values.length && (!permissions.has('event') || !permissions.has('worker') || !permissions.has('plugin.event'))) {
    throw new Error('control.event_access requires event, worker, and plugin.event permissions');
  }
  const seen = new Set();
  let topicCount = 0;
  return values.map((raw, index) => {
    const item = cloneJSON(raw || {});
    item.plugin = String(item.plugin || '').trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(item.plugin)) throw new Error(`control.event_access[${index}].plugin is invalid`);
    if (!Array.isArray(item.topic_prefixes) || item.topic_prefixes.length === 0) throw new Error(`control.event_access[${index}].topic_prefixes cannot be empty`);
    topicCount += item.topic_prefixes.length;
    if (topicCount > 256) throw new Error('control.event_access topic_prefixes exceed 256 entries');
    item.topic_prefixes = item.topic_prefixes.map((value, topicIndex) => {
      const prefix = eventTopic(value, `control.event_access[${index}].topic_prefixes[${topicIndex}]`);
      const namespace = `plugin.${item.plugin}`;
      if (prefix === 'plugin.lifecycle') throw new Error('event prefix plugin.lifecycle is reserved for the Veer lifecycle event');
      if (!eventTopicWithinPrefix(prefix, namespace)) throw new Error(`event prefix ${prefix} is outside ${namespace}`);
      const key = `${item.plugin}\0${prefix}`;
      if (seen.has(key)) throw new Error(`duplicate event access ${prefix}`);
      seen.add(key);
      return prefix;
    }).sort();
    return item;
  });
}

function normalizeMethods(values) {
  return [...new Set((Array.isArray(values) ? values : []).map((value) => String(value).trim().toLowerCase()).filter(Boolean))];
}

function normalizeTokenList(values, label, limit = 64) {
  if (values == null) return [];
  if (!Array.isArray(values) || values.length > limit) throw new Error(`${label} must be an array with at most ${limit} entries`);
  return [...new Set(values.map((value) => token(value, label)).filter(Boolean))].sort();
}

function normalizeUIResourceAccess(values, crossPlugin = false) {
  const field = crossPlugin ? 'resource_access' : 'resources';
  if (values == null) return [];
  if (!Array.isArray(values) || values.length > 64) throw new Error(`ui.register ${field} must be an array with at most 64 entries`);
  const seen = new Set();
  return values.map((raw, index) => {
    const item = cloneJSON(raw || {});
    const allowedFields = new Set(crossPlugin ? ['plugin', 'resource', 'methods'] : ['resource', 'methods']);
    for (const name of Object.keys(item)) {
      if (!allowedFields.has(name)) throw new Error(`ui.register ${field}[${index}] contains unknown field ${name}`);
    }
    const resource = token(item.resource, `ui.register ${field}[${index}].resource`);
    const methods = normalizeMethods(item.methods);
    const allowed = crossPlugin ? new Set(['list', 'get']) : new Set(['list', 'get', 'create', 'update', 'delete']);
    if (methods.length === 0 || methods.some((method) => !allowed.has(method))) {
      throw new Error(`ui.register ${field}[${index}].methods are invalid`);
    }
    const plugin = crossPlugin ? token(item.plugin, `ui.register resource_access[${index}].plugin`) : '';
    const key = `${plugin}\0${resource}`;
    if (seen.has(key)) throw new Error(`ui.register duplicate resource access ${plugin ? `${plugin}/` : ''}${resource}`);
    seen.add(key);
    const normalized = { resource, methods: methods.sort() };
    if (plugin) normalized.plugin = plugin;
    return normalized;
  }).sort((left, right) => `${left.plugin || ''}/${left.resource}`.localeCompare(`${right.plugin || ''}/${right.resource}`));
}

function normalizeUIRegistration(spec) {
  const item = cloneJSON(spec || {});
  const allowedFields = new Set(['static_dir', 'entry', 'sha256', 'page', 'page_title', 'resources', 'actions', 'resource_access']);
  for (const field of Object.keys(item)) {
    if (!allowedFields.has(field)) throw new Error(`ui.register contains unknown field ${field}`);
  }
  item.resources = normalizeUIResourceAccess(item.resources);
  item.actions = normalizeTokenList(item.actions, 'ui.register actions');
  item.resource_access = normalizeUIResourceAccess(item.resource_access, true);
  return item;
}

function semanticVersion(value, label) {
  const normalized = String(value || '').trim();
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.test(normalized)) {
    throw new Error(`${label} must be a semantic version such as 1.2.3`);
  }
  return normalized;
}

function versionConstraint(value, label) {
  const normalized = String(value == null || String(value).trim() === '' ? '*' : value).trim();
  if (normalized.length > 256 || normalized.includes('\0') || !/^[0-9A-Za-z*^~<>=|.,+\-\s]+$/.test(normalized)) {
    throw new Error(`${label} is an invalid semantic version constraint`);
  }
  return normalized;
}

function normalizeHookOrderReferences(values, label) {
  if (values == null) return [];
  if (!Array.isArray(values) || values.length > 32) throw new Error(`${label} must be an array with at most 32 entries`);
  const out = values.map((value) => {
    const parts = String(value || '').trim().toLowerCase().split('/').map((part) => part.trim());
    if (parts.length !== 2) throw new Error(`${label} reference must use plugin_id/hook_id`);
    return `${token(parts[0], label)}/${token(parts[1], label)}`;
  });
  return [...new Set(out)].sort();
}

function normalizeHookOrder(item, api) {
  item.before = normalizeHookOrderReferences(item.before, `${api}.before`);
  item.after = normalizeHookOrderReferences(item.after, `${api}.after`);
  const after = new Set(item.after);
  const conflict = item.before.find((reference) => after.has(reference));
  if (conflict) throw new Error(`${api} cannot declare ${conflict} in both before and after`);
  if (item.before.length === 0) delete item.before;
  if (item.after.length === 0) delete item.after;
  return item;
}

function normalizeHookPacketMetadata(item, api) {
  if (item.packet_metadata == null) {
    delete item.packet_metadata;
    return item;
  }
  if (!Array.isArray(item.packet_metadata) || item.packet_metadata.length > 16) {
    throw new Error(`${api}.packet_metadata must be an array with at most 16 entries`);
  }
  const slots = new Set();
  item.packet_metadata = item.packet_metadata.map((raw, index) => {
    const binding = cloneJSON(raw || {});
    if (!Number.isInteger(binding.slot) || binding.slot < 0 || binding.slot >= 16) {
      throw new Error(`${api}.packet_metadata[${index}].slot must be between 0 and 15`);
    }
    if (slots.has(binding.slot)) throw new Error(`${api}.packet_metadata contains duplicate local slot ${binding.slot}`);
    slots.add(binding.slot);
    const parts = String(binding.namespace || '').trim().toLowerCase().split('/');
    if (parts.length !== 2) throw new Error(`${api}.packet_metadata[${index}].namespace must use plugin_id/name`);
    binding.namespace = `${token(parts[0], `${api}.packet_metadata namespace owner`)}/${token(parts[1], `${api}.packet_metadata namespace`)}`;
    binding.schema_version = binding.schema_version == null || binding.schema_version === 0 ? 1 : binding.schema_version;
    if (!Number.isInteger(binding.schema_version) || binding.schema_version < 1 || binding.schema_version > 1000000) {
      throw new Error(`${api}.packet_metadata[${index}].schema_version must be between 1 and 1000000`);
    }
    binding.max_bytes = binding.max_bytes == null || binding.max_bytes === 0 ? 64 : binding.max_bytes;
    if (!Number.isInteger(binding.max_bytes) || binding.max_bytes < 1 || binding.max_bytes > 64) {
      throw new Error(`${api}.packet_metadata[${index}].max_bytes must be between 1 and 64`);
    }
    binding.access = String(binding.access || 'read').trim().toLowerCase();
    if (binding.access !== 'read' && binding.access !== 'read_write') {
      throw new Error(`${api}.packet_metadata[${index}].access must be read or read_write`);
    }
    return binding;
  }).sort((left, right) => left.slot - right.slot);
  if (item.packet_metadata.length === 0) delete item.packet_metadata;
  return item;
}

function normalizeObjectStateMaps(values) {
  if (values === undefined || values === null) return [];
  if (!Array.isArray(values) || values.length > 128) throw new Error('ebpf.loadObject.state_maps must be an array with at most 128 entries');
  const seen = new Set();
  const out = values.map((raw, index) => {
    const item = cloneJSON(raw || {});
    item.name = String(item.name || '').trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(item.name)) throw new Error(`ebpf.loadObject.state_maps[${index}].name is invalid`);
    if (RESERVED_EBPF_MAPS.has(item.name)) throw new Error(`ebpf.loadObject.state_maps[${index}].name is reserved`);
    if (seen.has(item.name)) throw new Error(`ebpf.loadObject.state_maps contains duplicate map ${item.name}`);
    seen.add(item.name);
    item.policy = String(item.policy || '').trim().toLowerCase();
    item.migrate_from = String(item.migrate_from || '').trim();
    const schemaVersion = Number(item.schema_version || 0);
    if (item.policy === 'preserve') {
      if (!Number.isInteger(schemaVersion) || schemaVersion < 1 || schemaVersion > 1000000) {
        throw new Error(`ebpf.loadObject.state_maps[${index}].schema_version is invalid`);
      }
      item.schema_version = schemaVersion;
      if (item.migrate_from) throw new Error(`ebpf.loadObject.state_maps[${index}].migrate_from is only valid for migrate policy`);
      delete item.migrate_from;
    } else if (item.policy === 'migrate') {
      if (!Number.isInteger(schemaVersion) || schemaVersion < 1 || schemaVersion > 1000000) {
        throw new Error(`ebpf.loadObject.state_maps[${index}].schema_version is invalid`);
      }
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(item.migrate_from) || item.migrate_from === item.name || RESERVED_EBPF_MAPS.has(item.migrate_from)) {
        throw new Error(`ebpf.loadObject.state_maps[${index}].migrate_from is invalid`);
      }
      item.schema_version = schemaVersion;
    } else if (item.policy === 'reset') {
      if (schemaVersion !== 0) throw new Error(`ebpf.loadObject.state_maps[${index}].schema_version must be omitted for reset policy`);
      if (item.migrate_from) throw new Error(`ebpf.loadObject.state_maps[${index}].migrate_from is only valid for migrate policy`);
      delete item.schema_version;
      delete item.migrate_from;
    } else {
      throw new Error(`ebpf.loadObject.state_maps[${index}].policy must be preserve, migrate, or reset`);
    }
    return item;
  });
  const contracts = new Map(out.map((item) => [item.name, item]));
  out.forEach((item, index) => {
    if (item.policy !== 'migrate') return;
    const source = contracts.get(item.migrate_from);
    if (!source || source.policy !== 'preserve' || source.schema_version >= item.schema_version) {
      throw new Error(`ebpf.loadObject.state_maps[${index}].migrate_from must reference an older preserved state map`);
    }
  });
  return out.sort((left, right) => left.name.localeCompare(right.name));
}

function globMatches(pattern, value) {
  const escaped = String(pattern).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(value);
}

function interfaceFromArgs(args) {
  for (const value of args) {
    if (typeof value === 'string' && value.trim()) return value.trim();
    if (!value || typeof value !== 'object') continue;
    for (const field of ['interface', 'dev', 'link', 'name', 'parent']) {
      if (typeof value[field] === 'string' && value[field].trim()) return value[field].trim();
    }
  }
  return '';
}

function createSharedState(fixtures = {}) {
  const state = {
    resources: new Map(),
    kv: new Map(),
    secrets: new Map(),
    blobs: new Map(),
    blobUploads: new Map(),
    maps: new Map(),
    timers: new Map(),
    calls: [],
    logs: [],
    publications: [],
    eventDeliveries: new Map(),
	operations: new Map(),
    ringDeliveries: [],
    metrics: new Map(),
    workers: new Map(),
    sequence: 0,
  };
  for (const [key, raw] of Object.entries(fixtures.kv || {})) {
    const item = raw && Object.prototype.hasOwnProperty.call(raw, 'data') ? raw : { data: raw };
    const recordKey = token(key, 'kv key');
    state.kv.set(recordKey, {
      key: recordKey, data: cloneJSON(item.data), enabled: true,
      revision: Number.isInteger(item.revision) && item.revision > 0 ? item.revision : 1,
      updated_at: item.updated_at || nowISO(),
    });
  }
  for (const [key, value] of Object.entries(fixtures.secrets || {})) state.secrets.set(token(key, 'secret key'), cloneJSON(value));
  for (const [resourceID, records] of Object.entries(fixtures.resources || {})) {
    const recordMap = new Map();
    for (const [key, raw] of Object.entries(records || {})) {
      const item = raw && Object.prototype.hasOwnProperty.call(raw, 'data') ? raw : { data: raw };
      recordMap.set(token(key, 'resource key'), {
        key: token(key, 'resource key'),
        data: cloneJSON(item.data),
        enabled: item.enabled !== false,
        revision: Number.isInteger(item.revision) && item.revision > 0 ? item.revision : 1,
        updated_at: item.updated_at || nowISO(),
      });
    }
    state.resources.set(token(resourceID, 'resource'), recordMap);
  }
	for (const [objectIDValue, maps] of Object.entries(fixtures.maps || {})) {
		const objectID = objectIDValue === '$default' ? '' : token(objectIDValue, 'object');
		for (const [mapNameValue, records] of Object.entries(maps || {})) {
			const mapName = token(mapNameValue, 'map');
			const recordMap = new Map();
			for (const [keyValue, valueValue] of Object.entries(records || {})) {
				const key = String(keyValue).trim().toLowerCase();
				const value = String(valueValue).trim().toLowerCase();
				if (!key || key.length % 2 !== 0 || !/^[0-9a-f]+$/.test(key)) throw new Error(`fixture map ${mapName} key must be even-length hex`);
				if (!value || value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) throw new Error(`fixture map ${mapName} value must be even-length hex`);
				recordMap.set(key, value);
			}
			state.maps.set(`${objectID}\0${mapName}`, recordMap);
		}
	}
  return state;
}

class VeerPluginTestHost {
  constructor(options = {}, sharedState = null, workerName = '') {
    if (!options.pluginDir) throw new Error('pluginDir is required');
    this.pluginDir = fs.realpathSync(path.resolve(options.pluginDir));
    this.timeoutMs = Number.isInteger(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
    this.adapters = Object.assign({}, options.adapters || {});
    this.state = sharedState || createSharedState(options.fixtures || {});
    this.workerName = workerName;
	this.moduleCache = new Map();
	this.moduleResolutions = new Map();
	this.moduleBytes = 0;
	this.moduleSequence = 0;
    this.registrationPhase = true;
    this.loaded = false;
    this.surface = {
      capabilities: [],
      virtual_interfaces: [],
      objects: [],
      hooks: [],
      resources: [],
      actions: [],
      services: [],
      event_subscriptions: [],
      ring_subscriptions: [],
      ui: null,
    };
    this.resourceContracts = new Map();
    this.actionContracts = new Map();
    this.manifest = this.#loadManifest();
    this.permissions = new Set((this.manifest.control && this.manifest.control.permissions) || []);
    this.netAccess = (this.manifest.control && this.manifest.control.net_access) || [];
    this.namespaceAccess = (this.manifest.control && this.manifest.control.namespace_access) || [];
    this.eventAccess = normalizeEventAccess(this.manifest, this.permissions);
  }

  #loadManifest() {
    const manifestPath = path.join(this.pluginDir, 'plugin.json');
    const stat = fs.lstatSync(manifestPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > (1 << 20)) {
      throw new Error('plugin.json must be a bounded regular file');
    }
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    manifest.id = token(manifest.id, 'plugin id');
    if (!manifest.control || !manifest.control.main) throw new Error('control.main is required by the test host');
    if (!Array.isArray(manifest.control.permissions)) manifest.control.permissions = [];
    return manifest;
  }

  load() {
    if (this.loaded) return this;
    const controlPath = this.#resolvePluginFile(this.manifest.control.main);
    const stat = fs.lstatSync(controlPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > MAX_SCRIPT_BYTES) {
      throw new Error('control.main must be a bounded regular file');
    }
    const source = fs.readFileSync(controlPath, 'utf8');
    if (this.manifest.control.sha256) {
      const digest = crypto.createHash('sha256').update(source).digest('hex');
      if (digest !== String(this.manifest.control.sha256).toLowerCase()) throw new Error('control.main sha256 mismatch');
    }
    const module = { exports: {} };
    const globals = this.#buildGlobals();
    this.context = vm.createContext(Object.assign({ module, exports: module.exports }, globals), {
      name: `veer-plugin-${this.manifest.id}${this.workerName ? `-${this.workerName}` : ''}`,
      codeGeneration: { strings: false, wasm: false },
    });
	const mainModuleID = this.#normalizeModuleID(this.manifest.control.main);
	this.moduleCache.set(mainModuleID, module);
	this.context.require = this.#createRequire(mainModuleID);
    const script = new vm.Script(source, { filename: controlPath, displayErrors: true });
    script.runInContext(this.context, { timeout: this.timeoutMs, displayErrors: true });
    this.#validateUI();
    this.#validateServices();
    this.exports = this.context.module.exports;
    if (!this.exports || (typeof this.exports !== 'object' && typeof this.exports !== 'function')) {
      throw new Error('control.main must export an object');
    }
    this.registrationPhase = false;
    this.loaded = true;
    return this;
  }

  #resolvePluginFile(relativePath) {
    const value = String(relativePath || '').trim();
    if (!value || path.isAbsolute(value) || value.includes('\0')) throw new Error('plugin path must be relative');
    const resolved = fs.realpathSync(path.resolve(this.pluginDir, value));
    if (resolved !== this.pluginDir && !resolved.startsWith(this.pluginDir + path.sep)) throw new Error('plugin path escapes pluginDir');
    return resolved;
  }

	#normalizeModuleID(value) {
		const normalized = path.posix.normalize(String(value || '').trim());
		if (!normalized || normalized === '.' || normalized === '..' || normalized.startsWith('../') ||
			path.posix.isAbsolute(normalized) || normalized.includes('\\') || normalized.includes('\0') ||
			path.posix.extname(normalized) !== '.js') {
			throw new Error('plugin module id must be a root-contained .js path');
		}
		return normalized;
	}

	#createRequire(referrer) {
		return (request) => this.#loadModule(referrer, request);
	}

	#resolveModule(referrer, request) {
		const raw = String(request || '').trim();
		if (!raw || raw.includes('\\') || raw.includes('\0') || path.posix.isAbsolute(raw) ||
			(!raw.startsWith('./') && !raw.startsWith('../'))) {
			throw new Error('require path must be relative to the current plugin module');
		}
		const base = path.posix.normalize(path.posix.join(path.posix.dirname(referrer), raw));
		if (base === '.' || base === '..' || base.startsWith('../')) throw new Error('required module escapes pluginDir');
		const extension = path.posix.extname(base);
		if (extension && extension !== '.js') throw new Error('plugin control modules must use the .js extension');
		const candidates = extension ? [base] : [`${base}.js`, path.posix.join(base, 'index.js')];
		for (const candidate of candidates) {
			let resolved;
			try {
				resolved = this.#resolvePluginFile(candidate);
			} catch (error) {
				if (error && error.code === 'ENOENT') continue;
				throw error;
			}
			const stat = fs.lstatSync(resolved);
			if (!stat.isFile() || stat.isSymbolicLink()) continue;
			if (stat.size > MAX_MODULE_BYTES) throw new Error(`plugin control module ${candidate} exceeds ${MAX_MODULE_BYTES} bytes`);
			const id = this.#normalizeModuleID(path.relative(this.pluginDir, resolved).split(path.sep).join('/'));
			return { id, source: fs.readFileSync(resolved, 'utf8') };
		}
		throw new Error(`plugin control module ${JSON.stringify(raw)} was not found from ${referrer}`);
	}

	#loadModule(referrer, request) {
		const resolutionKey = `${referrer}\0${String(request || '')}`;
		const known = this.moduleResolutions.get(resolutionKey);
		if (known && this.moduleCache.has(known)) return this.moduleCache.get(known).exports;
		const resolved = this.#resolveModule(referrer, request);
		this.moduleResolutions.set(resolutionKey, resolved.id);
		if (this.moduleCache.has(resolved.id)) return this.moduleCache.get(resolved.id).exports;
		if (this.moduleCache.size - 1 >= MAX_MODULE_COUNT) throw new Error(`plugin control module limit reached: ${MAX_MODULE_COUNT}`);
		const sourceBytes = Buffer.byteLength(resolved.source, 'utf8');
		if (this.moduleBytes + sourceBytes > MAX_MODULE_TOTAL_BYTES) throw new Error(`plugin control modules exceed ${MAX_MODULE_TOTAL_BYTES} total bytes`);

		const loadedModule = { exports: {} };
		this.moduleCache.set(resolved.id, loadedModule);
		this.moduleBytes += sourceBytes;
		let loaded = false;
		try {
			const wrapper = new vm.Script(`(function(exports,module,require,__filename,__dirname){\n${resolved.source}\n})`, {
				filename: resolved.id,
				displayErrors: true,
			}).runInContext(this.context, { timeout: this.timeoutMs, displayErrors: true });
			const callID = ++this.moduleSequence;
			const prefix = `__veerModule${callID}`;
			this.context[`${prefix}Wrapper`] = wrapper;
			this.context[`${prefix}Exports`] = loadedModule.exports;
			this.context[`${prefix}Module`] = loadedModule;
			this.context[`${prefix}Require`] = this.#createRequire(resolved.id);
			this.context[`${prefix}Filename`] = resolved.id;
			this.context[`${prefix}Dirname`] = path.posix.dirname(resolved.id);
			try {
				vm.runInContext(`${prefix}Wrapper(${prefix}Exports, ${prefix}Module, ${prefix}Require, ${prefix}Filename, ${prefix}Dirname)`, this.context, {
					timeout: this.timeoutMs,
					displayErrors: true,
				});
			} finally {
				for (const suffix of ['Wrapper', 'Exports', 'Module', 'Require', 'Filename', 'Dirname']) delete this.context[`${prefix}${suffix}`];
			}
			loaded = true;
			return loadedModule.exports;
		} finally {
			if (!loaded) {
				this.moduleCache.delete(resolved.id);
				this.moduleBytes -= sourceBytes;
			}
		}
	}

  #requirePermission(permission, api, registrationOnly = false) {
    if (registrationOnly && !this.registrationPhase) throw new Error(`${api} is only available during plugin registration`);
    if (this.registrationPhase && !REGISTRATION_PERMISSIONS.has(permission) && api !== 'crypto.sha256File') {
      throw new Error(`permission ${permission} is unavailable during plugin registration`);
    }
    if (!this.permissions.has(permission)) throw new Error(`permission ${permission} is required by ${api}`);
  }

  #requireAnyPermission(permissions, api) {
    if (this.registrationPhase) throw new Error(`${api} is unavailable during plugin registration`);
    if (!permissions.some((permission) => this.permissions.has(permission))) {
      throw new Error(`${api} requires one of permissions ${permissions.join(', ')}`);
    }
  }

  #registerUnique(collection, spec, api) {
    const item = cloneJSON(spec || {});
    item.id = token(item.id, `${api}.id`);
    if (collection.some((existing) => existing.id === item.id)) throw new Error(`${api} duplicate id ${item.id}`);
    collection.push(item);
    return item;
  }

  #buildGlobals() {
    const registerVIF = (spec, defaultType) => {
      this.#requirePermission('plugin.register', 'plugin.virtualInterface', true);
      const item = this.#registerUnique(this.surface.virtual_interfaces, spec, 'plugin.virtualInterface');
      if (!item.type && defaultType) item.type = defaultType;
    };
    const registerResource = (spec) => {
      this.#requirePermission('plugin.register', 'plugin.resource', true);
      const item = this.#registerUnique(this.surface.resources, spec, 'plugin.resource');
      item.methods = normalizeMethods(item.methods);
      item.control_methods = normalizeMethods(item.control_methods || item.methods);
      item.runtime_update = String(item.runtime_update || 'manual').trim().toLowerCase();
      this.resourceContracts.set(item.id, item);
    };
    const registerAction = (spec) => {
      this.#requirePermission('plugin.register', 'plugin.action', true);
      const item = this.#registerUnique(this.surface.actions, spec, 'plugin.action');
      item.runtime_update = String(item.runtime_update || 'none').trim().toLowerCase();
      normalizeSchemaContract(item, 'request');
      normalizeSchemaContract(item, 'response');
      this.actionContracts.set(item.id, item);
    };
    const registerService = (spec) => {
      this.#requirePermission('plugin.register', 'plugin.service', true);
      const limit = Number(API_CONTRACT.runtime && API_CONTRACT.runtime.resource_limits && API_CONTRACT.runtime.resource_limits.services_per_plugin || 64);
      if (this.surface.services.length >= limit) throw new Error(`plugin.service limit reached: ${limit}`);
      const item = this.#registerUnique(this.surface.services, spec, 'plugin.service');
      item.version = semanticVersion(item.version, 'plugin.service.version');
      item.description = String(item.description || '').trim();
      if (Buffer.byteLength(item.description, 'utf8') > 1024 || item.description.includes('\0')) {
        throw new Error('plugin.service.description exceeds 1024 bytes or contains NUL');
      }
      if (!item.description) delete item.description;
      item.actions = normalizeTokenList(item.actions, 'plugin.service.actions');
      item.resources = normalizeTokenList(item.resources, 'plugin.service.resources');
      if (item.actions.length === 0 && item.resources.length === 0) {
        throw new Error('plugin.service must expose at least one action or resource');
      }
    };
    const privileged = (permission, api) => (...args) => {
      this.#requirePermission(permission, api);
      return this.#adapter(api, args);
    };
    const scopedNamespace = (request = {}, api = 'net') => {
      const namespace = String(request && (request.namespace || request.netns) || 'host').trim().toLowerCase() || 'host';
      if (namespace === 'host') return namespace;
      this.#requirePermission('net.namespace', api);
      this.#requireNamespaceAccess(namespace);
      return namespace;
    };
    const scopedNamespaceFromArgs = (args, api) => {
      const request = args.find((value) => value && typeof value === 'object' && !Array.isArray(value) && (value.namespace || value.netns));
      return scopedNamespace(request || {}, api);
    };
    const linkMethod = (name, operation) => (...args) => {
      this.#requirePermission('net.admin', `net.link.${name}`);
      scopedNamespaceFromArgs(args, `net.link.${name}`);
      this.#requireNetAccess(operation, interfaceFromArgs(args), name === 'list');
      return this.#adapter(`net.link.${name}`, args);
    };
    const addrMethod = (name) => (request = {}) => {
      this.#requirePermission('net.admin', `net.addr.${name}`);
      scopedNamespace(request, `net.addr.${name}`);
      this.#requireNetAccess('addr.write', request.interface || request.dev || request.link || '');
      return this.#adapter(`net.addr.${name}`, [request]);
    };
    const routeAccess = (request = {}) => {
      const rawNexthops = request.nexthops == null ? request.next_hops : request.nexthops;
      if (rawNexthops != null) {
        if (!Array.isArray(rawNexthops) || rawNexthops.length < 1 || rawNexthops.length > 64) {
          throw new Error('route nexthops count must be between 1 and 64');
        }
        if (String(request.dev || request.interface || '').trim() || String(request.gateway || request.gw || '').trim()) {
          throw new Error('route dev and gateway cannot be combined with nexthops');
        }
        const seen = new Set();
        for (const [index, nexthop] of rawNexthops.entries()) {
          if (!nexthop || typeof nexthop !== 'object' || Array.isArray(nexthop)) throw new Error(`route nexthop ${index} must be an object`);
          const dev = String(nexthop.dev || nexthop.interface || nexthop.link || '').trim();
          const gateway = String(nexthop.gateway || nexthop.gw || '').trim();
          const weight = Number(nexthop.weight == null ? 1 : nexthop.weight);
          if (!Number.isInteger(weight) || weight < 1 || weight > 256) throw new Error(`route nexthop ${index} weight must be between 1 and 256`);
          if (nexthop.onlink === true && !gateway) throw new Error(`route nexthop ${index} onlink requires gateway`);
          const key = `${dev}\0${gateway}`;
          if (seen.has(key)) throw new Error(`route nexthop ${index} duplicates dev/gateway`);
          seen.add(key);
          this.#requireNetAccess('route.write', dev);
        }
        return;
      }
      this.#requireNetAccess('route.write', request.dev || request.interface || '');
    };
    const routeMethod = (name) => (request = {}) => {
      this.#requirePermission('net.admin', `net.route.${name}`);
      scopedNamespace(request, `net.route.${name}`);
      routeAccess(request);
      return this.#adapter(`net.route.${name}`, [request]);
    };
    const ruleAccess = (request = {}) => {
      const interfaces = [...new Set([request.iif, request.oif].map((value) => String(value || '').trim()).filter(Boolean))];
      if (interfaces.length === 0) this.#requireNetAccess('rule.write', '', true);
      else interfaces.forEach((interfaceName) => this.#requireNetAccess('rule.write', interfaceName));
    };
    const ruleMethod = (name) => (request = {}) => {
      this.#requirePermission('net.admin', `net.rule.${name}`);
      scopedNamespace(request, `net.rule.${name}`);
      ruleAccess(request);
      return this.#adapter(`net.rule.${name}`, [request]);
    };
    const neighAccess = (request = {}) => {
      this.#requireNetAccess('neigh.write', request.interface || request.dev || request.link || '');
    };
    const neighMethod = (name) => (request = {}) => {
      this.#requirePermission('net.admin', `net.neigh.${name}`);
      scopedNamespace(request, `net.neigh.${name}`);
      neighAccess(request);
      return this.#adapter(`net.neigh.${name}`, [request]);
    };
    const inventoryMethod = (api, operation, allowFamily = false) => (request = {}) => {
      this.#requirePermission('net.admin', api);
      scopedNamespace(request, api);
      const interfaceName = String(request.interface || request.dev || request.link || '').trim();
      if (!interfaceName) throw new Error(`${api}: interface is required`);
      this.#requireNetAccess(operation, interfaceName);
      const limit = Number(request.limit == null ? 1024 : request.limit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 4096) throw new Error(`${api}: limit must be between 1 and 4096`);
      if (allowFamily) {
        const family = String(request.family || 'all').trim().toLowerCase();
        if (!['all', 'ipv4', 'ipv6', '4', '6', 'inet', 'inet6'].includes(family)) {
          throw new Error(`${api}: family must be all, ipv4, or ipv6`);
        }
      }
      return this.#adapter(api, [request]);
    };
    const netTransactionMethod = (group, validateAccess) => (operations) => {
      this.#requirePermission('net.admin', `net.${group}.transaction`);
      if (!Array.isArray(operations) || operations.length < 1 || operations.length > 128) {
        throw new Error(`net.${group}.transaction operation count must be between 1 and 128`);
      }
      let namespace = null;
      operations.forEach((item, index) => {
        if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error(`net.${group}.transaction operation ${index} is invalid`);
        const op = String(item.op || item.operation || '').toLowerCase();
        if (op !== 'replace' && op !== 'delete') throw new Error(`net.${group}.transaction operation ${index} op must be replace or delete`);
        const request = item.request && typeof item.request === 'object' ? item.request : item;
        const currentNamespace = scopedNamespace(request, `net.${group}.transaction`);
        if (namespace == null) namespace = currentNamespace;
        else if (namespace !== currentNamespace) throw new Error(`net.${group}.transaction all operations must target the same namespace`);
        validateAccess(request);
      });
      return this.#adapter(`net.${group}.transaction`, [operations]);
    };
    const transportMethod = (group, name, permission, operation) => (request = {}) => {
      this.#requirePermission(permission, `net.${group}.${name}`);
      scopedNamespace(request, `net.${group}.${name}`);
      this.#requireNetEndpointAccess(operation, request.interface || request.dev || '', request);
      return this.#adapter(`net.${group}.${name}`, [request]);
    };
    const namespaceMethod = (name) => (...args) => {
      this.#requirePermission('net.namespace', `net.namespace.${name}`);
      if (!['list', 'owned'].includes(name)) {
        const value = name === 'ensure' ? (args[0] || {}).name : args[0];
        this.#requireNamespaceAccess(value);
      }
      return this.#adapter(`net.namespace.${name}`, args);
    };
    const tunTapMethod = (name) => (request = {}) => {
      this.#requirePermission('net.tuntap', `net.tuntap.${name}`);
      if (['list', 'owned'].includes(name)) return this.#adapter(`net.tuntap.${name}`, []);
      {
        this.#requireNamespaceAccess(request.namespace || request.netns || 'host');
        this.#requireNetAccess('tuntap', request.name || request.interface || request.link || '');
      }
      return this.#adapter(`net.tuntap.${name}`, [request]);
    };

    return {
      plugin: Object.freeze({
        host: () => ({
          runtime_version: API_CONTRACT.runtime.runtime_version,
          control_api_abi: API_CONTRACT.runtime.control_api_abi,
          tc_pipeline_abi: API_CONTRACT.runtime.tc_pipeline_abi,
          os: process.platform,
          arch: process.arch,
          kernel_release: 'test',
          core_priority: API_CONTRACT.runtime.core_priority,
          features: API_CONTRACT.runtime.features.slice(),
          available_features: API_CONTRACT.runtime.features.slice(),
          feature_status: Object.fromEntries(API_CONTRACT.runtime.features.map((feature) => [feature, {available: true}])),
          resource_limits: cloneJSON(API_CONTRACT.runtime.resource_limits),
        }),
        capabilities: (...values) => {
          this.#requirePermission('plugin.register', 'plugin.capabilities', true);
          const input = values.length === 1 && Array.isArray(values[0]) ? values[0] : values;
          this.surface.capabilities = [...new Set(input.map((value) => token(value, 'capability')))];
        },
        resource: registerResource,
        action: registerAction,
        service: registerService,
        virtualInterface: (spec) => registerVIF(spec, ''),
        pipelineNode: (spec) => registerVIF(spec, 'pipeline'),
        handoff: (spec) => registerVIF(spec, 'handoff'),
      }),
      pipeline: Object.freeze({
        node: (spec) => registerVIF(spec, 'pipeline'),
        handoff: (spec) => registerVIF(spec, 'handoff'),
        attach: (spec) => {
          this.#requirePermission('hook.attach', 'pipeline.attach', true);
          const input = Object.assign({}, cloneJSON(spec || {}), { engine: 'tc' });
          if (!input.stage && input.direction) {
            if (input.phase === 'after_apply') input.stage = input.direction === 'reply' ? 'post_reply_apply' : 'post_apply';
            else input.stage = input.direction === 'reply' ? 'pre_reply' : 'pre_forward';
          }
          const hook = this.#registerUnique(this.surface.hooks, input, 'pipeline.attach');
          normalizeHookOrder(hook, 'pipeline.attach');
          normalizeHookPacketMetadata(hook, 'pipeline.attach');
        },
      }),
      hooks: Object.freeze({
        attach: (spec) => {
          this.#requirePermission('hook.attach', 'hooks.attach', true);
          const hook = this.#registerUnique(this.surface.hooks, spec, 'hooks.attach');
          normalizeHookOrder(hook, 'hooks.attach');
          normalizeHookPacketMetadata(hook, 'hooks.attach');
        },
      }),
      ebpf: Object.freeze({
        loadObject: (spec) => {
          this.#requirePermission('ebpf.load', 'ebpf.loadObject', true);
          const item = this.#registerUnique(this.surface.objects, spec, 'ebpf.loadObject');
          item.state_maps = normalizeObjectStateMaps(item.state_maps);
        },
        mapPut: (objectID, mapName, keyHex, valueHex) => this.#mapPut(objectID, mapName, keyHex, valueHex),
        mapTransaction: (request) => this.#mapTransaction(request),
        mapGet: (objectID, mapName, keyHex) => this.#mapGet(objectID, mapName, keyHex),
        mapGetPerCPU: privileged('ebpf.map_read', 'ebpf.mapGetPerCPU'),
        mapScan: (...args) => this.#mapScan(...args),
        mapDelete: (objectID, mapName, keyHex) => this.#mapDelete(objectID, mapName, keyHex),
        mapClear: (objectID, mapName) => this.#mapClear(objectID, mapName),
        ringRead: privileged('ebpf.map_read', 'ebpf.ringRead'),
        ringSubscribe: (spec) => this.#ringSubscribe(spec),
        ringStats: () => this.#ringStats(),
      }),
      ui: Object.freeze({
        register: (spec) => {
          this.#requirePermission('ui', 'ui.register', true);
          if (this.surface.ui) throw new Error('ui.register duplicate registration');
          this.surface.ui = normalizeUIRegistration(spec);
        },
      }),
      kv: Object.freeze({
        get: (key) => this.#kvGet(key),
        set: (key, value) => this.#kvSet(key, value),
        delete: (key) => this.#kvDelete(key),
        list: (page) => this.#mapRecords(this.state.kv, page),
      }),
      secret: Object.freeze({
        get: (key) => this.#secretGet(key),
        set: (key, value) => this.#secretSet(key, value),
        delete: (key) => this.#secretDelete(key),
      }),
      blob: Object.freeze({
        begin: (request) => this.#blobBegin(request),
        write: (request) => this.#blobWrite(request),
        commit: (request) => this.#blobCommit(request),
        abort: (request) => this.#blobAbort(request),
        put: (request) => this.#blobPut(request),
        read: (request) => this.#blobRead(request),
        stat: (request) => this.#blobStat(request),
        list: (request) => this.#blobList(request),
        delete: (request) => this.#blobDelete(request),
        verify: (request) => this.#blobVerify(request),
      }),
      resources: Object.freeze({
        get: (resource, key) => this.#resourceGet(resource, key),
        set: (resource, key, data, enabled, apply) => this.#resourceSet(resource, key, data, enabled, apply),
        delete: (resource, key, apply) => this.#resourceDelete(resource, key, apply),
        list: (resource, page) => this.#resourceList(resource, page),
        transaction: (operations, options) => this.#resourceTransaction(operations, options),
      }),
      plugins: Object.freeze({
        resources: Object.freeze({
          get: privileged('plugin.resource', 'plugins.resources.get'),
          list: privileged('plugin.resource', 'plugins.resources.list'),
          set: privileged('plugin.resource', 'plugins.resources.set'),
          delete: privileged('plugin.resource', 'plugins.resources.delete'),
          transaction: privileged('plugin.resource', 'plugins.resources.transaction'),
        }),
        actions: Object.freeze({ call: privileged('plugin.action', 'plugins.actions.call') }),
        services: Object.freeze({
          list: (query) => this.#serviceList(query),
          resolve: (query) => this.#serviceResolve(query),
          call: (request) => this.#serviceCall(request),
        }),
      }),
      timer: Object.freeze({
        setTimeout: (name, delayMs, payload) => this.#timerSet(name, 'timeout', delayMs, payload),
        setInterval: (name, delayMs, payload) => this.#timerSet(name, 'interval', delayMs, payload),
        clear: (name) => this.#timerClear(name),
        list: () => this.#timerList(),
      }),
      worker: Object.freeze({
        call: (name, handler, payload) => this.#workerCall(name, handler, payload),
        dispatch: (name, handler, payload) => this.#workerDispatch(name, handler, payload),
        list: () => this.#workerList(),
        stats: () => ({ pending_requests: 0, pending_bytes: 0, peak_pending_requests: 0, peak_pending_bytes: 0, rejected_requests: 0, request_limit: 256, byte_limit: 16 << 20 }),
      }),
      events: Object.freeze({
        subscribe: (spec) => this.#eventSubscribe(spec),
        publish: (topic, payload, options) => this.#eventPublish(topic, payload, options),
        stats: () => ({ published: this.state.publications.length, subscriptions: cloneJSON(this.surface.event_subscriptions) }),
        deadLetters: (options) => this.#eventDeadLetters(options),
        retry: (deliveryID) => this.#eventRetry(deliveryID),
        discard: (deliveryID) => this.#eventDiscard(deliveryID),
      }),
	  operations: Object.freeze({
		begin: (request) => this.#operationBegin(request),
		get: (id) => this.#operationGet(id),
		getByKey: (key) => this.#operationGetByKey(key),
		list: (request) => this.#operationList(request),
		claim: (id, revision) => this.#operationClaim(id, revision),
		checkpoint: (id, revision, request) => this.#operationCheckpoint(id, revision, request),
		complete: (id, revision, result) => this.#operationComplete(id, revision, result),
		retry: (id, revision, request) => this.#operationTransition(id, revision, 'retry_wait', request),
		fail: (id, revision, request) => this.#operationTransition(id, revision, 'failed', request),
		cancel: (id, revision, request) => this.#operationTransition(id, revision, 'cancelled', request || {}),
		remove: (id) => this.#operationRemove(id),
		stats: () => this.#operationStats(),
	  }),
      metrics: Object.freeze({
        counter: (...args) => this.#metricCounter(args[0], args[1], args[2], args.length),
        gauge: (name, value, labels) => this.#metricGauge(name, value, labels),
        delete: (...args) => this.#metricDelete(args[0], args[1], args.length > 1),
        clear: () => this.#metricClear(),
        list: () => this.#metricList(),
      }),
      crypto: Object.freeze({
        md5: (...values) => {
          this.#requirePermission('crypto', 'crypto.md5');
          return crypto.createHash('md5').update(Buffer.concat(values.map((value) => Buffer.from(String(value))))).digest('hex');
        },
        randomBytes: (length) => {
          this.#requirePermission('crypto', 'crypto.randomBytes');
          const size = Number(length);
          if (!Number.isInteger(size) || size < 1 || size > 4096) throw new Error('crypto.randomBytes length is out of range');
          return crypto.randomBytes(size).toString('hex');
        },
        sha256File: (file) => {
          this.#requirePermission('crypto', 'crypto.sha256File');
          return crypto.createHash('sha256').update(fs.readFileSync(this.#resolvePluginFile(file))).digest('hex');
        },
      }),
      net: Object.freeze({
        prefix: Object.freeze({ subnet: (request) => this.#adapter('net.prefix.subnet', [request]) }),
        lease: Object.freeze({
          list: () => { this.#requirePermission('net.admin', 'net.lease.list'); return this.#adapter('net.lease.list', []); },
          restore: (type, key) => { this.#requirePermission('net.admin', 'net.lease.restore'); return this.#adapter('net.lease.restore', [type, key]); },
        }),
        namespace: Object.freeze(Object.fromEntries(['get', 'list', 'ensure', 'delete', 'release', 'owned'].map((name) => [name, namespaceMethod(name)]))),
        tuntap: Object.freeze(Object.fromEntries(['ensure', 'close', 'read', 'write', 'list', 'owned'].map((name) => [name, tunTapMethod(name)]))),
        l2: Object.freeze(Object.fromEntries(['send', 'recv', 'recvMany', 'exchange', 'exchangeMany'].map((name) => [name, transportMethod('l2', name, 'net.l2', 'l2')]))),
        udp: Object.freeze(Object.fromEntries(['send', 'recv', 'exchange'].map((name) => [name, transportMethod('udp', name, 'net.udp', 'udp')]))),
        socket: Object.freeze(Object.fromEntries(['open', 'listen', 'accept', 'read', 'write', 'close', 'status', 'list', 'watch', 'unwatch', 'watchList'].map((name) => [name, (...args) => this.#socketCall(name, args)]))),
        http: Object.freeze({request: transportMethod('http', 'request', 'net.http', 'http')}),
        dns: Object.freeze({lookup: transportMethod('dns', 'lookup', 'net.dns', 'dns')}),
        link: Object.freeze({
          get: linkMethod('get', 'link.read'), list: linkMethod('list', 'link.read'),
          ensureBridge: linkMethod('ensureBridge', 'link.create'), ensureVeth: linkMethod('ensureVeth', 'link.create'),
          ensureDummy: linkMethod('ensureDummy', 'link.create'), ensureMacvlan: linkMethod('ensureMacvlan', 'link.create'),
          ensureVLAN: linkMethod('ensureVLAN', 'link.create'), ensureVRF: linkMethod('ensureVRF', 'link.create'),
          delete: linkMethod('delete', 'link.delete'), release: linkMethod('release', 'link.delete'), owned: linkMethod('owned', 'link.read'),
          setMaster: linkMethod('setMaster', 'link.master'), clearMaster: linkMethod('clearMaster', 'link.master'),
          setUp: linkMethod('setUp', 'link.state'), setMTU: linkMethod('setMTU', 'link.state'), setARP: linkMethod('setARP', 'link.state'),
          setPromiscuous: linkMethod('setPromiscuous', 'link.state'), getOffloads: linkMethod('getOffloads', 'link.read'),
          setOffloads: linkMethod('setOffloads', 'link.offload'), setGSO: linkMethod('setGSO', 'link.offload'),
        }),
        addr: Object.freeze({ replace: addrMethod('replace'), delete: addrMethod('delete') }),
        route: Object.freeze({ replace: routeMethod('replace'), delete: routeMethod('delete'), transaction: netTransactionMethod('route', routeAccess) }),
        rule: Object.freeze({ replace: ruleMethod('replace'), delete: ruleMethod('delete'), transaction: netTransactionMethod('rule', ruleAccess) }),
        neigh: Object.freeze({
          list: inventoryMethod('net.neigh.list', 'neigh.read', true),
          replace: neighMethod('replace'), delete: neighMethod('delete'), transaction: netTransactionMethod('neigh', neighAccess),
        }),
        bridge: Object.freeze({fdb: Object.freeze({list: inventoryMethod('net.bridge.fdb.list', 'bridge.fdb.read')})}),
      }),
      log: Object.freeze(Object.fromEntries(['debug', 'info', 'warn', 'error'].map((level) => [level, (...values) => this.#log(level, values)]))),
    };
  }

  #adapter(api, args) {
    this.state.calls.push({ api, args: cloneJSON(args), at: nowISO(), worker: this.workerName || '' });
    const adapter = this.adapters[api];
    if (typeof adapter !== 'function') throw new Error(`${api} requires an explicit test adapter`);
    return cloneJSON(adapter(...cloneJSON(args), this));
  }

  #validateUI() {
    const ui = this.surface.ui;
    if (!ui) return;
    for (const access of ui.resources) {
      const resource = this.resourceContracts.get(access.resource);
      if (!resource) throw new Error(`ui.resources references undeclared resource ${access.resource}`);
      for (const method of access.methods) {
        if (!resource.methods.includes(method)) {
          throw new Error(`ui.resources method ${method} is not exposed by resource ${access.resource}`);
        }
      }
    }
    for (const action of ui.actions) {
      if (!this.actionContracts.has(action)) throw new Error(`ui.actions references undeclared action ${action}`);
    }
    const controlAccess = this.manifest.control && Array.isArray(this.manifest.control.resource_access)
      ? this.manifest.control.resource_access
      : [];
    for (const access of ui.resource_access) {
      for (const method of access.methods) {
        const granted = controlAccess.some((item) => {
          if (!item || String(item.plugin || '').trim().toLowerCase() !== access.plugin ||
              String(item.resource || '').trim().toLowerCase() !== access.resource) return false;
          return normalizeMethods(item.methods).includes(method);
        });
        if (!granted) {
          throw new Error(`ui.resource_access ${access.plugin}/${access.resource} method ${method} is not granted by control.resource_access`);
        }
      }
    }
  }

  #validateServices() {
    for (const service of this.surface.services) {
      for (const action of service.actions) {
        if (!this.actionContracts.has(action)) throw new Error(`service ${service.id} references undeclared action ${action}`);
      }
      for (const resource of service.resources) {
        if (!this.resourceContracts.has(resource)) throw new Error(`service ${service.id} references undeclared resource ${resource}`);
      }
    }
  }

  #serviceQuery(value, required, api) {
    if (value == null) {
      if (required) throw new Error(`${api}: query is required`);
      value = {};
    }
    if (typeof value !== 'object' || Array.isArray(value) || Object.prototype.toString.call(value) !== '[object Object]') {
      throw new Error(`${api}: query must be an object`);
    }
    const query = {};
    const service = String(value.service || '').trim().toLowerCase();
    if (!service && required) throw new Error(`${api}: service is required`);
    if (service) query.service = token(service, `${api}.service`);
    query.version = versionConstraint(value.version, `${api}.version`);
    const provider = String(value.provider || '').trim().toLowerCase();
    if (provider) query.provider = token(provider, `${api}.provider`);
    return query;
  }

  #serviceList(query) {
    this.#requireAnyPermission(['plugin.action', 'plugin.resource'], 'plugins.services.list');
    const result = this.#adapter('plugins.services.list', [this.#serviceQuery(query, false, 'plugins.services.list')]);
    if (!Array.isArray(result)) throw new Error('plugins.services.list adapter must return an array');
    return result;
  }

  #serviceResolve(query) {
    this.#requireAnyPermission(['plugin.action', 'plugin.resource'], 'plugins.services.resolve');
    const result = this.#adapter('plugins.services.resolve', [this.#serviceQuery(query, true, 'plugins.services.resolve')]);
    if (!result || typeof result !== 'object' || Array.isArray(result)) {
      throw new Error('plugins.services.resolve adapter must return a provider object');
    }
    return result;
  }

  #serviceCall(request) {
    this.#requirePermission('plugin.action', 'plugins.services.call');
    if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error('plugins.services.call: request is required');
    const query = this.#serviceQuery(request, true, 'plugins.services.call');
    const action = token(request.action, 'plugins.services.call.action');
    return this.#adapter('plugins.services.call', [Object.assign(query, {action, payload: cloneJSON(request.payload == null ? {} : request.payload)})]);
  }

  #requireNetAccess(operation, interfaceName, allowAnyInterface = false) {
    const name = String(interfaceName || '').trim();
    const matches = this.netAccess.filter((entry) => {
      const operations = Array.isArray(entry.operations) ? entry.operations : [];
      const interfaces = Array.isArray(entry.interfaces) ? entry.interfaces : [];
      return operations.includes(operation) && (allowAnyInterface || interfaces.some((pattern) => globMatches(pattern, name)));
    });
    if (!matches.length) throw new Error(`net_access ${operation} for interface ${name || '<empty>'} is not declared`);
    return matches;
  }

  #requireNetEndpointAccess(operation, interfaceName, request = {}) {
    const entries = this.#requireNetAccess(operation, interfaceName);
    let host = '';
    let remoteIP = String(request.remote_ip || request.dst_ip || request.target_ip || request.resolver_ip || request.server_ip || request.dns_server || '').trim();
    let remotePort = Number(request.remote_port || request.dst_port || request.target_port || request.resolver_port || request.server_port || request.dns_port || request.port || 0);
    if (operation === 'http') {
      let parsed;
      try {
        parsed = new URL(String(request.url || ''));
      } catch (_) {
        throw new Error('net.http.request URL is invalid');
      }
      host = String(parsed.hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
      remotePort = Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80));
      if (net.isIP(host)) {
        remoteIP = host;
        host = '';
      } else {
        remoteIP = '';
      }
    } else if (operation === 'dns') {
      host = String(request.name || '').replace(/\.$/, '').toLowerCase();
      remotePort = Number(request.resolver_port || request.server_port || request.dns_port || 53);
    }
    const allowed = entries.some((entry) => {
      const hosts = Array.isArray(entry.remote_hosts) ? entry.remote_hosts.map((value) => String(value).toLowerCase()) : [];
      const ports = Array.isArray(entry.remote_ports) ? entry.remote_ports.map(Number) : [];
      const cidrs = Array.isArray(entry.remote_cidrs) ? entry.remote_cidrs.map(String) : [];
      if (hosts.length && !hosts.some((pattern) => pattern === '*' || pattern === host || (pattern.startsWith('*.') && host.length > pattern.length - 1 && host.endsWith(pattern.slice(1))))) return false;
      if (ports.length && !ports.includes(remotePort)) return false;
      if (cidrs.length && remoteIP && !cidrs.some((cidr) => this.#cidrContains(cidr, remoteIP))) return false;
      return true;
    });
    if (!allowed) {
      const endpoint = host || remoteIP || '<unspecified>';
      throw new Error(`net_access ${operation} endpoint ${endpoint}${remotePort ? ':' + remotePort : ''} for interface ${interfaceName || '<empty>'} is not declared`);
    }
  }

  #cidrContains(cidr, ip) {
    const [network, prefixText] = String(cidr).split('/');
    const family = net.isIP(network);
    const addressFamily = net.isIP(ip);
    const prefix = Number(prefixText);
    if (!family || family !== addressFamily || !Number.isInteger(prefix)) return false;
    try {
      const list = new net.BlockList();
      list.addSubnet(network, prefix, family === 6 ? 'ipv6' : 'ipv4');
      return list.check(ip, family === 6 ? 'ipv6' : 'ipv4');
    } catch (_) {
      return false;
    }
  }

  #requireNamespaceAccess(namespace) {
    const name = String(namespace || 'host').trim().toLowerCase();
    if (!name || name.length > 63 || name.includes('/') || name.includes('\\') || /\s/.test(name)) {
      throw new Error(`namespace ${name || '<empty>'} is invalid`);
    }
    if (!this.namespaceAccess.some((pattern) => globMatches(String(pattern).toLowerCase(), name))) {
      throw new Error(`namespace_access for ${name} is not declared`);
    }
  }

  #resourceContract(resourceID) {
    const id = token(resourceID, 'resource');
    const contract = this.resourceContracts.get(id);
    if (!contract) throw new Error(`resource ${id} is not registered`);
    return contract;
  }

  #resourceRecords(resourceID) {
    const id = token(resourceID, 'resource');
    if (!this.state.resources.has(id)) this.state.resources.set(id, new Map());
    return this.state.resources.get(id);
  }

  #requireControlMethod(contract, method) {
    this.#requirePermission('resource', `resources.${method}`);
    if (!contract.control_methods.includes(method)) throw new Error(`resource ${contract.id} does not allow ${method}`);
  }

  #resourceGet(resourceID, key) {
    const contract = this.#resourceContract(resourceID);
    this.#requireControlMethod(contract, 'get');
    return cloneJSON(this.#resourceRecords(contract.id).get(token(key, 'resource key')) || null);
  }

  #resourceList(resourceID, page = {}) {
    const contract = this.#resourceContract(resourceID);
    this.#requireControlMethod(contract, 'list');
    return this.#mapRecords(this.#resourceRecords(contract.id), page, true);
  }

  #resourceSet(resourceID, key, data, enabled = true, apply = false) {
    const contract = this.#resourceContract(resourceID);
    const recordKey = token(key, 'resource key');
    const records = this.#resourceRecords(contract.id);
    const existing = records.get(recordKey);
    this.#requireControlMethod(contract, existing ? 'update' : 'create');
    const record = {
      key: recordKey, data: cloneJSON(data), enabled: enabled !== false,
      revision: existing ? existing.revision + 1 : 1, updated_at: nowISO(),
    };
    records.set(recordKey, record);
    if (apply) this.#applyResource(contract, recordKey);
    return undefined;
  }

  #resourceDelete(resourceID, key, apply = false) {
    const contract = this.#resourceContract(resourceID);
    this.#requireControlMethod(contract, 'delete');
    const recordKey = token(key, 'resource key');
    this.#resourceRecords(contract.id).delete(recordKey);
    if (apply) this.#applyResource(contract, recordKey);
    return undefined;
  }

  #resourceTransaction(operations, options = {}) {
    this.#requirePermission('resource', 'resources.transaction');
    if (!Array.isArray(operations) || operations.length === 0) throw new Error('resources.transaction requires operations');
    const backup = new Map();
    for (const [id, records] of this.state.resources) backup.set(id, new Map([...records].map(([key, value]) => [key, cloneJSON(value)])));
    const touched = new Set();
    try {
      for (const operation of operations) {
        const op = String(operation.op || '').toLowerCase();
        if (op === 'set') this.#resourceSet(operation.resource, operation.key, operation.data, operation.enabled, false);
        else if (op === 'delete') this.#resourceDelete(operation.resource, operation.key, false);
        else throw new Error(`unsupported resource transaction operation ${op}`);
        touched.add(token(operation.resource, 'resource'));
      }
      if (options.apply) for (const id of touched) this.#applyResource(this.#resourceContract(id), '');
    } catch (error) {
      this.state.resources = backup;
      throw error;
    }
    return { status: 'completed', operations: operations.length, mutated_resources: touched.size, applied: options.apply === true };
  }

  #applyResource(contract, key) {
    if (contract.runtime_update === 'plugin_reconcile') return this.reconcile();
    if (contract.runtime_update === 'runtime_apply') {
      return this.run('onResourceApply', this.#context('resource_apply', {
        resource: { id: contract.id, runtime_update: contract.runtime_update }, key,
        records: this.#resourceListUnsafe(contract.id),
      }));
    }
    return undefined;
  }

  #mapRecords(map, page = {}, structured = false) {
    this.#requirePermission(structured ? 'resource' : 'kv', structured ? 'resources.list' : 'kv.list');
    const limit = Number.isInteger(page && page.limit) ? Math.max(1, Math.min(1000, page.limit)) : 100;
    const offset = Number.isInteger(page && page.offset) ? Math.max(0, page.offset) : 0;
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b)).slice(offset, offset + limit).map(([key, value], index) => {
      if (structured) return cloneJSON(value);
      return Object.assign({ id: offset + index + 1 }, cloneJSON(value));
    });
  }

  #resourceListUnsafe(resourceID) {
    return [...this.#resourceRecords(resourceID).values()].sort((a, b) => a.key.localeCompare(b.key)).map(cloneJSON);
  }

	#requireOperationAPI(api) {
	  this.#requirePermission('operation', api);
	  if (this.workerName) throw new Error(`${api} is only available in the plugin main VM`);
	}

	#operationLimits() {
	  return Object.assign({
		max_records_per_plugin: 1024,
		max_field_bytes: 256 << 10,
		max_plugin_bytes: 64 << 20,
		default_list_limit: 100,
		max_list_limit: 500,
		max_retry_delay_ms: 7 * 24 * 60 * 60 * 1000,
	  }, API_CONTRACT.operations || {});
	}

	#operationJSON(value, label) {
	  const cloned = cloneJSON(value === undefined ? null : value);
	  const bytes = Buffer.byteLength(JSON.stringify(cloned), 'utf8');
	  if (bytes > Number(this.#operationLimits().max_field_bytes)) throw new Error(`${label} exceeds the operation field limit`);
	  return cloned;
	}

	#operationByID(id) {
	  const normalized = String(id || '').trim().toLowerCase();
	  if (!/^[0-9a-f]{32}$/.test(normalized)) throw new Error('operation id is invalid');
	  for (const item of this.state.operations.values()) if (item.id === normalized) return item;
	  return null;
	}

	#operationView(item) {
	  if (!item) return null;
	  const value = cloneJSON(item);
	  value.resumable = value.status === 'pending' || value.status === 'running' ||
		(value.status === 'retry_wait' && value.next_attempt_unix_ms <= Date.now());
	  return value;
	}

	#operationBytes(item) {
	  return item ? Buffer.byteLength(JSON.stringify(item), 'utf8') + 128 : 0;
	}

	#operationStorageBytes() {
	  let bytes = 0;
	  for (const item of this.state.operations.values()) bytes += this.#operationBytes(item);
	  return bytes;
	}

	#requireOperationStorage(candidate, previous = null) {
	  const projected = this.#operationStorageBytes() - this.#operationBytes(previous) + this.#operationBytes(candidate);
	  if (projected > Number(this.#operationLimits().max_plugin_bytes)) throw new Error('operation storage byte limit reached');
	}

	#operationBegin(request = {}) {
	  this.#requireOperationAPI('operations.begin');
	  if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error('operations.begin request is required');
	  const key = token(request.key, 'operation key');
	  const kind = token(request.kind, 'operation kind');
	  const input = this.#operationJSON(request.input, 'operation input');
	  const state = this.#operationJSON(request.state, 'operation state');
	  const existing = this.state.operations.get(key);
	  if (existing) {
		const terminal = ['completed', 'failed', 'cancelled'].includes(existing.status);
		if (!request.restart || !terminal) {
		  if (existing.kind !== kind || canonicalJSON(existing.input) !== canonicalJSON(input)) {
			throw new Error(`operation key ${key} already belongs to a different request`);
		  }
		  return this.#operationView(existing);
		}
		const restarted = Object.assign({}, existing, {
		  kind, status: 'pending', phase: '', input, state, result: null, error: null,
		  attempts: 0, revision: existing.revision + 1, next_attempt_unix_ms: 0, updated_at: nowISO(),
		});
		this.#requireOperationStorage(restarted, existing);
		Object.assign(existing, restarted);
		return this.#operationView(existing);
	  }
	  if (this.state.operations.size >= Number(this.#operationLimits().max_records_per_plugin)) throw new Error('operation count limit reached');
	  const now = nowISO();
	  const item = {
		id: crypto.randomBytes(16).toString('hex'), key, kind, status: 'pending', phase: '', input, state,
		result: null, error: null, attempts: 0, revision: 1, next_attempt_unix_ms: 0, created_at: now, updated_at: now,
	  };
	  this.#requireOperationStorage(item);
	  this.state.operations.set(key, item);
	  return this.#operationView(item);
	}

	#operationGet(id) {
	  this.#requireOperationAPI('operations.get');
	  return this.#operationView(this.#operationByID(id));
	}

	#operationGetByKey(key) {
	  this.#requireOperationAPI('operations.getByKey');
	  return this.#operationView(this.state.operations.get(token(key, 'operation key')) || null);
	}

	#operationList(request = {}) {
	  this.#requireOperationAPI('operations.list');
	  if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error('operations.list request must be an object');
	  const kind = request.kind ? token(request.kind, 'operation kind') : '';
	  const status = String(request.status || '').trim().toLowerCase();
	  const statuses = new Set((this.#operationLimits().statuses || ['pending', 'running', 'retry_wait', 'completed', 'failed', 'cancelled']));
	  if (status && !statuses.has(status)) throw new Error(`invalid operation status ${status}`);
	  if (request.resumable && status) throw new Error('operation status and resumable cannot be combined');
	  const limit = request.limit == null ? Number(this.#operationLimits().default_list_limit) : Number(request.limit);
	  if (!Number.isInteger(limit) || limit < 1 || limit > Number(this.#operationLimits().max_list_limit)) throw new Error('operation list limit is invalid');
	  return [...this.state.operations.values()]
		.filter((item) => (!kind || item.kind === kind) && (!status || item.status === status))
		.map((item) => this.#operationView(item))
		.filter((item) => !request.resumable || item.resumable)
		.slice(0, limit);
	}

	#operationRequired(id, revision, api) {
	  const item = this.#operationByID(id);
	  if (!item) throw new Error(`${api}: operation was not found`);
	  const expected = Number(revision);
	  if (!Number.isInteger(expected) || expected < 1 || item.revision !== expected) throw new Error(`${api}: operation is stale`);
	  return item;
	}

	#operationClaim(id, revision) {
	  this.#requireOperationAPI('operations.claim');
	  const item = this.#operationRequired(id, revision, 'operations.claim');
	  if (!['pending', 'running'].includes(item.status) && !(item.status === 'retry_wait' && item.next_attempt_unix_ms <= Date.now())) {
		throw new Error('operations.claim: operation is terminal or not due');
	  }
	  const candidate = Object.assign({}, item, {status: 'running', attempts: item.attempts + 1, revision: item.revision + 1, next_attempt_unix_ms: 0, error: null, updated_at: nowISO()});
	  this.#requireOperationStorage(candidate, item);
	  Object.assign(item, candidate);
	  return this.#operationView(item);
	}

	#operationCheckpoint(id, revision, request = {}) {
	  this.#requireOperationAPI('operations.checkpoint');
	  const item = this.#operationRequired(id, revision, 'operations.checkpoint');
	  if (item.status !== 'running') throw new Error('operations.checkpoint: operation is not running');
	  const candidate = Object.assign({}, item, {
		phase: request.phase ? token(request.phase, 'operation phase') : '',
		state: this.#operationJSON(request.state, 'operation state'),
		revision: item.revision + 1,
		updated_at: nowISO(),
	  });
	  this.#requireOperationStorage(candidate, item);
	  Object.assign(item, candidate);
	  return this.#operationView(item);
	}

	#operationComplete(id, revision, result) {
	  this.#requireOperationAPI('operations.complete');
	  const item = this.#operationRequired(id, revision, 'operations.complete');
	  if (item.status !== 'running') throw new Error('operations.complete: operation is not running');
	  const candidate = Object.assign({}, item, {
		status: 'completed', result: this.#operationJSON(result, 'operation result'), error: null,
		revision: item.revision + 1, updated_at: nowISO(),
	  });
	  this.#requireOperationStorage(candidate, item);
	  Object.assign(item, candidate);
	  return this.#operationView(item);
	}

	#operationTransition(id, revision, status, request = {}) {
	  const api = `operations.${status === 'retry_wait' ? 'retry' : status === 'cancelled' ? 'cancel' : 'fail'}`;
	  this.#requireOperationAPI(api);
	  const item = this.#operationRequired(id, revision, api);
	  if (item.status !== 'running') throw new Error(`${api}: operation is not running`);
	  const delay = Number(request.delay_ms || 0);
	  if (!Number.isInteger(delay) || delay < 0 || delay > Number(this.#operationLimits().max_retry_delay_ms)) throw new Error(`${api}: delay_ms is invalid`);
	  const candidate = Object.assign({}, item, {
		status,
		error: String(request.error || ''),
		next_attempt_unix_ms: status === 'retry_wait' ? Date.now() + delay : 0,
		revision: item.revision + 1,
		updated_at: nowISO(),
	  });
	  if (request.phase) candidate.phase = token(request.phase, 'operation phase');
	  if (Object.prototype.hasOwnProperty.call(request, 'state')) candidate.state = this.#operationJSON(request.state, 'operation state');
	  this.#requireOperationStorage(candidate, item);
	  Object.assign(item, candidate);
	  return this.#operationView(item);
	}

	#operationRemove(id) {
	  this.#requireOperationAPI('operations.remove');
	  const item = this.#operationByID(id);
	  if (!item || !['completed', 'failed', 'cancelled'].includes(item.status)) throw new Error('operations.remove: operation is missing or nonterminal');
	  this.state.operations.delete(item.key);
	}

	#operationStats() {
	  this.#requireOperationAPI('operations.stats');
	  const byStatus = {};
	  let bytes = 0;
	  for (const item of this.state.operations.values()) {
		byStatus[item.status] = (byStatus[item.status] || 0) + 1;
		bytes += this.#operationBytes(item);
	  }
	  return {total: this.state.operations.size, by_status: byStatus, bytes, record_limit: Number(this.#operationLimits().max_records_per_plugin), byte_limit: Number(this.#operationLimits().max_plugin_bytes)};
	}

  #kvGet(key) {
    this.#requirePermission('kv', 'kv.get');
    return cloneJSON(this.state.kv.get(token(key, 'kv key')) || null);
  }

  #kvSet(key, value) {
    this.#requirePermission('kv', 'kv.set');
    const recordKey = token(key, 'kv key');
    const existing = this.state.kv.get(recordKey);
    this.state.kv.set(recordKey, {
      key: recordKey, data: cloneJSON(value), enabled: true,
      revision: existing ? existing.revision + 1 : 1, updated_at: nowISO(),
    });
  }

  #kvDelete(key) {
    this.#requirePermission('kv', 'kv.delete');
    this.state.kv.delete(token(key, 'kv key'));
  }

  #secretSet(key, value) {
    this.#requirePermission('secret', 'secret.set');
    this.state.secrets.set(token(key, 'secret key'), cloneJSON(value));
  }

  #secretGet(key) {
    this.#requirePermission('secret', 'secret.get');
    return cloneJSON(this.state.secrets.get(token(key, 'secret key')) ?? null);
  }

  #secretDelete(key) {
    this.#requirePermission('secret', 'secret.delete');
    this.state.secrets.delete(token(key, 'secret key'));
  }

  #blobRequest(request, api) {
    this.#requirePermission('blob', api);
    if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error(`${api} request must be an object`);
    return request;
  }

  #blobPayload(request, api) {
    const encoded = String(request.payload_hex == null ? request.data == null ? '' : request.data : request.payload_hex).trim().toLowerCase();
    if (!/^(?:[0-9a-f]{2})*$/.test(encoded)) throw new Error(`${api} payload_hex is invalid`);
    const data = Buffer.from(encoded, 'hex');
    if (data.length > 1 << 20) throw new Error(`${api} payload exceeds 1048576 bytes`);
    return data;
  }

  #blobBegin(request = {}) {
    request = this.#blobRequest(request, 'blob.begin');
    const key = token(request.key, 'blob key');
    const expectedBytes = Number(request.expected_bytes || 0);
    const maxObjectBytes = Number(API_CONTRACT.runtime && API_CONTRACT.runtime.resource_limits && API_CONTRACT.runtime.resource_limits.blob_object_bytes || 64 << 20);
    if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 0 || expectedBytes > maxObjectBytes) throw new Error('blob.begin expected_bytes is invalid');
    const expectedSHA256 = String(request.sha256 || request.expected_sha256 || '').trim().toLowerCase();
    if (expectedSHA256 && !/^[0-9a-f]{64}$/.test(expectedSHA256)) throw new Error('blob.begin sha256 is invalid');
    const uploadID = `upload_${++this.state.sequence}`;
    const upload = {upload_id: uploadID, key, data: Buffer.alloc(0), expected_bytes: expectedBytes, expected_sha256: expectedSHA256, created_at: nowISO()};
    this.state.blobUploads.set(uploadID, upload);
    return this.#blobUploadInfo(upload);
  }

  #blobWrite(request = {}) {
    request = this.#blobRequest(request, 'blob.write');
    const uploadID = String(request.upload_id || request.upload || '').trim().toLowerCase();
    const upload = this.state.blobUploads.get(uploadID);
    if (!upload) throw new Error('blob.write upload was not found');
    const offset = Number(request.offset || 0);
    if (!Number.isSafeInteger(offset) || offset !== upload.data.length) throw new Error(`blob.write offset does not match ${upload.data.length}`);
    const data = this.#blobPayload(request, 'blob.write');
    if (!data.length) throw new Error('blob.write payload cannot be empty');
    upload.data = Buffer.concat([upload.data, data]);
    if (upload.expected_bytes && upload.data.length > upload.expected_bytes) throw new Error('blob.write exceeds expected_bytes');
    return this.#blobUploadInfo(upload);
  }

  #blobCommit(request = {}) {
    request = this.#blobRequest(request, 'blob.commit');
    const uploadID = String(request.upload_id || request.upload || '').trim().toLowerCase();
    const upload = this.state.blobUploads.get(uploadID);
    if (!upload) throw new Error('blob.commit upload was not found');
    if (upload.expected_bytes && upload.data.length !== upload.expected_bytes) throw new Error('blob.commit size does not match expected_bytes');
    const digest = crypto.createHash('sha256').update(upload.data).digest('hex');
    if (upload.expected_sha256 && digest !== upload.expected_sha256) throw new Error('blob.commit sha256 mismatch');
    const existing = this.state.blobs.get(upload.key);
    const now = nowISO();
    const info = {key: upload.key, bytes: upload.data.length, sha256: digest, created_at: existing ? existing.info.created_at : now, updated_at: now};
    this.state.blobs.set(upload.key, {data: Buffer.from(upload.data), info});
    this.state.blobUploads.delete(uploadID);
    return cloneJSON(info);
  }

  #blobAbort(request = {}) {
    request = this.#blobRequest(request, 'blob.abort');
    const uploadID = String(request.upload_id || request.upload || '').trim().toLowerCase();
    return {aborted: this.state.blobUploads.delete(uploadID)};
  }

  #blobPut(request = {}) {
    request = this.#blobRequest(request, 'blob.put');
    const key = token(request.key, 'blob key');
    const data = this.#blobPayload(request, 'blob.put');
    const expected = String(request.sha256 || request.expected_sha256 || '').trim().toLowerCase();
    const digest = crypto.createHash('sha256').update(data).digest('hex');
    if (expected && expected !== digest) throw new Error('blob.put sha256 mismatch');
    const existing = this.state.blobs.get(key);
    const now = nowISO();
    const info = {key, bytes: data.length, sha256: digest, created_at: existing ? existing.info.created_at : now, updated_at: now};
    this.state.blobs.set(key, {data: Buffer.from(data), info});
    return cloneJSON(info);
  }

  #blobRead(request = {}) {
    request = this.#blobRequest(request, 'blob.read');
    const item = this.state.blobs.get(token(request.key, 'blob key'));
    if (!item) return null;
    const offset = Number(request.offset || 0);
    const maxBytes = Number(request.max_bytes || 64 << 10);
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > item.data.length || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 1 << 20) throw new Error('blob.read range is invalid');
    const data = item.data.subarray(offset, offset + maxBytes);
    return {blob: cloneJSON(item.info), offset, payload_hex: data.toString('hex'), bytes: data.length, eof: offset + data.length >= item.data.length};
  }

  #blobStat(request = {}) {
    request = this.#blobRequest(request, 'blob.stat');
    const item = this.state.blobs.get(token(request.key, 'blob key'));
    return item ? cloneJSON(item.info) : null;
  }

  #blobList(request = {}) {
    request = this.#blobRequest(request || {}, 'blob.list');
    const after = request.after ? token(request.after, 'blob after') : '';
    const limit = Number(request.limit || 100);
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new Error('blob.list limit is invalid');
    return [...this.state.blobs.entries()].filter(([key]) => key > after).sort(([left], [right]) => left.localeCompare(right)).slice(0, limit).map(([, value]) => cloneJSON(value.info));
  }

  #blobDelete(request = {}) {
    request = this.#blobRequest(request, 'blob.delete');
    return {deleted: this.state.blobs.delete(token(request.key, 'blob key'))};
  }

  #blobVerify(request = {}) {
    request = this.#blobRequest(request, 'blob.verify');
    const item = this.state.blobs.get(token(request.key, 'blob key'));
    if (!item) throw new Error('blob.verify blob was not found');
    const digest = crypto.createHash('sha256').update(item.data).digest('hex');
    if (digest !== item.info.sha256) throw new Error('blob.verify sha256 mismatch');
    return {verified: true, blob: cloneJSON(item.info)};
  }

  #blobUploadInfo(upload) {
    const info = {upload_id: upload.upload_id, key: upload.key, bytes: upload.data.length, created_at: upload.created_at};
    if (upload.expected_bytes) info.expected_bytes = upload.expected_bytes;
    if (upload.expected_sha256) info.expected_sha256 = upload.expected_sha256;
    return info;
  }

  #mapKey(objectID, mapName) {
    const object = String(objectID || '').trim() ? token(objectID, 'object') : '';
    return `${object}\0${token(mapName, 'map')}`;
  }

  #mapPut(objectID, mapName, keyHex, valueHex) {
    this.#requirePermission('ebpf.map_write', 'ebpf.mapPut');
    const mapKey = this.#mapKey(objectID, mapName);
    if (!this.state.maps.has(mapKey)) this.state.maps.set(mapKey, new Map());
    this.state.maps.get(mapKey).set(String(keyHex).toLowerCase(), String(valueHex).toLowerCase());
  }

  #mapGet(objectID, mapName, keyHex) {
    this.#requirePermission('ebpf.map_read', 'ebpf.mapGet');
    return this.state.maps.get(this.#mapKey(objectID, mapName))?.get(String(keyHex).toLowerCase()) ?? null;
  }

  #mapTransaction(request) {
    this.#requirePermission('ebpf.map_write', 'ebpf.mapTransaction');
    if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error('ebpf.mapTransaction request must be an object');
    if (!Array.isArray(request.operations) || request.operations.length < 1 || request.operations.length > 256) {
      throw new Error('ebpf.mapTransaction operation count must be between 1 and 256');
    }
    const normalizeHex = (value, label) => {
      const normalized = String(value || '').trim().replace(/^0x/i, '').replace(/[\s:_-]/g, '').toLowerCase();
      if (!normalized || normalized.length % 2 !== 0 || !/^[0-9a-f]+$/.test(normalized)) throw new Error(`${label} must be non-empty even-length hex`);
      return normalized;
    };
    const normalizeMutation = (raw, index, commit = false) => {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error(`ebpf.mapTransaction ${commit ? 'commit' : `operation ${index}`} must be an object`);
      const op = String(raw.op || raw.operation || (commit ? 'put' : '')).trim().toLowerCase();
      if (op !== 'put' && op !== 'delete') throw new Error(`ebpf.mapTransaction operation ${index} op must be put or delete`);
      if (commit && op !== 'put') throw new Error('ebpf.mapTransaction commit op must be put');
      const objectValue = raw.object || raw.object_id;
      const objectID = String(objectValue || '').trim() ? token(objectValue, 'object') : '';
      const mapName = token(raw.map || raw.map_name, 'map');
      if (RESERVED_EBPF_MAPS.has(mapName)) throw new Error(`ebpf.mapTransaction map ${mapName} is reserved`);
      const mutation = {op, object: objectID, map: mapName, key: normalizeHex(raw.key || raw.key_hex, 'map key')};
      if (op === 'put') mutation.value = normalizeHex(raw.value || raw.value_hex, 'map value');
      return mutation;
    };
    const operations = request.operations.map((item, index) => normalizeMutation(item, index));
    const commit = request.commit == null ? null : normalizeMutation(request.commit, operations.length, true);
    const mutations = commit ? operations.concat([commit]) : operations;
    const seen = new Set();
    let bytes = 0;
    for (const mutation of mutations) {
      const slot = `${mutation.object}\0${mutation.map}\0${mutation.key}`;
      if (seen.has(slot)) throw new Error(`ebpf.mapTransaction duplicate map slot ${mutation.map}/${mutation.key}`);
      seen.add(slot);
      bytes += Buffer.from(mutation.key, 'hex').length + (mutation.value ? Buffer.from(mutation.value, 'hex').length : 0);
    }
    if (bytes > 1 << 20) throw new Error('ebpf.mapTransaction key/value bytes exceed 1048576');
    for (const mutation of mutations) {
      const mapKey = this.#mapKey(mutation.object, mutation.map);
      if (!this.state.maps.has(mapKey)) this.state.maps.set(mapKey, new Map());
      if (mutation.op === 'put') this.state.maps.get(mapKey).set(mutation.key, mutation.value);
      else this.state.maps.get(mapKey).delete(mutation.key);
    }
    return {status: 'completed', operations: operations.length, committed: commit !== null};
  }

  #mapScan(...args) {
    this.#requirePermission('ebpf.map_read', 'ebpf.mapScan');
    if (args.length !== 2 && args.length !== 3) throw new Error('ebpf.mapScan requires map/options or object/map/options');
    const objectID = args.length === 3 ? args[0] : '';
    const mapName = args.length === 3 ? args[1] : args[0];
    const options = args.length === 3 ? args[2] : args[1];
    if (!options || typeof options !== 'object' || Array.isArray(options)) throw new Error('ebpf.mapScan options must be an object');
    const limit = options.limit == null ? 64 : Number(options.limit);
    const maxBytes = options.max_bytes == null ? 256 << 10 : Number(options.max_bytes);
    if (!Number.isInteger(limit) || limit < 1 || limit > 256) throw new Error('ebpf.mapScan limit must be between 1 and 256');
    if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 1 << 20) throw new Error('ebpf.mapScan max_bytes must be between 1 and 1048576');
    const cursor = String(options.cursor || '').toLowerCase();
    const records = [...(this.state.maps.get(this.#mapKey(objectID, mapName)) || new Map()).entries()]
      .sort(([left], [right]) => left.localeCompare(right));
    let start = 0;
    if (cursor) {
      const index = records.findIndex(([key]) => key === cursor);
      start = index >= 0 ? index + 1 : records.findIndex(([key]) => key > cursor);
      if (start < 0) start = records.length;
    }
    const entries = [];
    let bytes = 0;
    let index = start;
    for (; index < records.length && entries.length < limit; index++) {
      const [key, value] = records[index];
      const entryBytes = Buffer.from(key, 'hex').length + Buffer.from(value, 'hex').length;
      if (entryBytes > maxBytes - bytes) {
        if (!entries.length) throw new Error(`ebpf.mapScan entry size ${entryBytes} exceeds scan byte limit ${maxBytes}`);
        break;
      }
      entries.push({ key, value });
      bytes += entryBytes;
    }
    const done = index >= records.length;
    return { entries, cursor: done || !entries.length ? '' : entries[entries.length - 1].key, done };
  }

  #mapDelete(objectID, mapName, keyHex) {
    this.#requirePermission('ebpf.map_write', 'ebpf.mapDelete');
    this.state.maps.get(this.#mapKey(objectID, mapName))?.delete(String(keyHex).toLowerCase());
  }

  #mapClear(objectID, mapName) {
    this.#requirePermission('ebpf.map_write', 'ebpf.mapClear');
    this.state.maps.get(this.#mapKey(objectID, mapName))?.clear();
  }

  #socketCall(name, args) {
    const request = args.find((value) => value && typeof value === 'object') || {};
    if (name === 'watch' || name === 'unwatch' || name === 'watchList') {
      this.#requirePermission('worker', `net.socket.${name}`);
      if (!this.permissions.has('net.tcp') && !this.permissions.has('net.udp')) {
        throw new Error(`net.socket.${name}: permission net.tcp or net.udp is required`);
      }
      return this.#adapter(`net.socket.${name}`, args);
    }
    const network = String(request.network || request.type || 'tcp').toLowerCase();
    const udp = network.startsWith('udp');
    this.#requirePermission(udp ? 'net.udp' : 'net.tcp', `net.socket.${name}`);
    if (name === 'open') this.#requireNetEndpointAccess(udp ? 'udp' : 'tcp', interfaceFromArgs(args), request);
    else if (name === 'listen') this.#requireNetAccess(udp ? 'udp' : 'tcp', interfaceFromArgs(args));
    else if (name === 'write' && (request.remote_ip || request.peer_ip || request.dst_ip)) {
      this.#requireNetEndpointAccess(udp ? 'udp' : 'tcp', interfaceFromArgs(args), request);
    }
    return this.#adapter(`net.socket.${name}`, args);
  }

  #timerSet(name, kind, delayMs, payload) {
    this.#requirePermission('timer', `timer.set${kind === 'interval' ? 'Interval' : 'Timeout'}`);
    const id = token(name, 'timer');
    const delay = Number(delayMs);
    if (!Number.isInteger(delay) || delay < 10 || delay > 86400000) throw new Error('timer delay is out of range');
    this.state.timers.set(id, { name: id, kind, delay_ms: delay, payload: cloneJSON(payload || {}), next_fire: new Date(Date.now() + delay).toISOString() });
  }

  #timerClear(name) {
    this.#requirePermission('timer', 'timer.clear');
    this.state.timers.delete(token(name, 'timer'));
  }

  #timerList() {
    this.#requirePermission('timer', 'timer.list');
    return cloneJSON([...this.state.timers.values()]);
  }

  #worker(name) {
    const id = token(name, 'worker');
    if (!this.state.workers.has(id)) {
      const worker = new VeerPluginTestHost({ pluginDir: this.pluginDir, timeoutMs: this.timeoutMs, adapters: this.adapters }, this.state, id).load();
      this.state.workers.set(id, worker);
    }
    return this.state.workers.get(id);
  }

  #workerCall(name, handler, payload) {
    this.#requirePermission('worker', 'worker.call');
    if (this.workerName) throw new Error('worker.call is unavailable inside plugin workers');
    const id = token(name, 'worker');
    const target = handlerName(handler, 'worker handler');
    return this.#worker(id).run(target, this.#context('worker', { worker: { name: id, handler: target }, payload: cloneJSON(payload || {}) }), false);
  }

  #workerDispatch(name, handler, payload) {
    const result = this.#workerCall(name, handler, payload);
    this.state.calls.push({ api: 'worker.dispatch.result', args: [cloneJSON(result)], at: nowISO(), worker: String(name) });
    return { queued: true, worker: token(name, 'worker'), handler: handlerName(handler, 'worker handler') };
  }

  #workerList() {
    this.#requirePermission('worker', 'worker.list');
    return [...this.state.workers.entries()].map(([name]) => ({ name, mode: 'worker', executing: false, queue_depth: 0, pending_requests: 0, pending_bytes: 0 }));
  }

  #ringSubscribe(spec) {
    this.#requirePermission('ebpf.load', 'ebpf.ringSubscribe', true);
    if (!this.permissions.has('ebpf.map_read') || !this.permissions.has('worker')) {
      throw new Error('ebpf.ringSubscribe requires ebpf.map_read and worker permissions');
    }
    const item = this.#registerUnique(this.surface.ring_subscriptions, spec, 'ebpf.ringSubscribe');
    item.object = token(item.object, 'ring object');
    item.map = String(item.map || '').trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(item.map) || RESERVED_EBPF_MAPS.has(item.map)) throw new Error('ring map is invalid or reserved');
    item.worker = token(item.worker, 'ring worker');
    item.handler = handlerName(item.handler, 'ring handler');
    item.queue_size = Number(item.queue_size || 16);
    item.max_records = Number(item.max_records || 64);
    item.max_bytes = Number(item.max_bytes || (64 << 10));
    item.poll_timeout_ms = Number(item.poll_timeout_ms || 500);
    if (!Number.isInteger(item.queue_size) || item.queue_size < 1 || item.queue_size > 64) throw new Error('ring queue_size is out of range');
    if (!Number.isInteger(item.max_records) || item.max_records < 1 || item.max_records > 128) throw new Error('ring max_records is out of range');
    if (!Number.isInteger(item.max_bytes) || item.max_bytes < 1 || item.max_bytes > (256 << 10)) throw new Error('ring max_bytes is out of range');
    if (!Number.isInteger(item.poll_timeout_ms) || item.poll_timeout_ms < 10 || item.poll_timeout_ms > 1000) throw new Error('ring poll_timeout_ms is out of range');
    if (!this.surface.objects.some((object) => object.id === item.object)) throw new Error(`ring subscription references unknown object ${item.object}`);
    if (this.surface.ring_subscriptions.some((other) => other !== item && other.object === item.object && other.map === item.map)) {
      throw new Error(`ring map ${item.object}:${item.map} already has a consumer`);
    }
  }

  #ringStats() {
    this.#requirePermission('ebpf.map_read', 'ebpf.ringStats');
    const subscriptions = this.surface.ring_subscriptions.map((spec) => {
      const delivered = this.state.ringDeliveries.filter((entry) => entry.subscription === spec.id);
      return Object.assign({}, cloneJSON(spec), {
        pending: 0, pending_bytes: 0, peak_pending_bytes: 0,
        read_calls: delivered.length, read_records: delivered.reduce((sum, entry) => sum + entry.records, 0),
        read_bytes: delivered.reduce((sum, entry) => sum + entry.bytes, 0), read_dropped_records: 0,
        enqueued_batches: delivered.length, delivered_batches: delivered.length,
        dropped_batches: 0, dropped_records: 0, read_errors: 0, handler_errors: 0,
      });
    });
    return {
      subscription_count: subscriptions.length, pending: 0, pending_bytes: 0, pending_byte_limit: 16 << 20,
      read_records: subscriptions.reduce((sum, item) => sum + item.read_records, 0),
      read_bytes: subscriptions.reduce((sum, item) => sum + item.read_bytes, 0), read_dropped_records: 0,
      enqueued_batches: subscriptions.reduce((sum, item) => sum + item.enqueued_batches, 0),
      delivered_batches: subscriptions.reduce((sum, item) => sum + item.delivered_batches, 0),
      dropped_batches: 0, dropped_records: 0, read_errors: 0, handler_errors: 0, subscriptions,
    };
  }

  #eventSubscribe(spec) {
    this.#requirePermission('event', 'events.subscribe', true);
    if (!this.permissions.has('worker')) throw new Error('events.subscribe requires worker permission');
    const item = this.#registerUnique(this.surface.event_subscriptions, spec, 'events.subscribe');
    item.topic = eventTopic(item.topic, 'event topic');
    item.match = String(item.match || 'exact').trim().toLowerCase();
    if (!['exact', 'prefix'].includes(item.match)) throw new Error('event match must be exact or prefix');
    item.worker = token(item.worker || 'events', 'event worker');
    item.handler = handlerName(item.handler || 'onEvent', 'event handler');
    item.queue_size = Number(item.queue_size == null ? 64 : item.queue_size);
    if (!Number.isInteger(item.queue_size) || item.queue_size < 1 || item.queue_size > 256) throw new Error('event queue_size must be between 1 and 256');
    item.delivery = String(item.delivery || 'volatile').trim().toLowerCase();
    if (!['volatile', 'durable'].includes(item.delivery)) throw new Error('event delivery must be volatile or durable');
    if (item.delivery === 'durable') {
      if (item.topic === 'net' || item.topic.startsWith('net.')) throw new Error('durable delivery is not available for high-rate network events');
      item.max_attempts = Number(item.max_attempts == null ? 8 : item.max_attempts);
      item.retry_delay_ms = Number(item.retry_delay_ms == null ? 500 : item.retry_delay_ms);
      if (!Number.isInteger(item.max_attempts) || item.max_attempts < 1 || item.max_attempts > 16) throw new Error('event max_attempts must be between 1 and 16');
      if (!Number.isInteger(item.retry_delay_ms) || item.retry_delay_ms < 100 || item.retry_delay_ms > 60000) throw new Error('event retry_delay_ms must be between 100 and 60000');
    } else if (item.max_attempts != null || item.retry_delay_ms != null) {
      throw new Error('event max_attempts and retry_delay_ms require durable delivery');
    }
    normalizeSchemaContract(item);
    const source = customEventSource(item.topic);
    if (source && source !== this.manifest.id) {
      if (!this.permissions.has('plugin.event')) throw new Error(`event topic ${item.topic} requires plugin.event permission`);
      const allowed = this.eventAccess.some((access) => access.plugin === source && access.topic_prefixes.some((prefix) => eventTopicWithinPrefix(item.topic, prefix)));
      if (!allowed) throw new Error(`event topic ${item.topic} is not declared in control.event_access`);
    }
  }

  #eventPublish(topic, payload, options = {}) {
    this.#requirePermission('event', 'events.publish');
    const normalized = eventTopic(topic, 'event topic');
    if (!normalized.startsWith(`plugin.${this.manifest.id}.`)) throw new Error(`events.publish topic must use plugin.${this.manifest.id}.*`);
    const schemaVersion = eventSchemaVersion(options && options.schema_version, 'events.publish');
    const publication = {
      topic: normalized, payload: cloneJSON(payload || {}), schema_version: schemaVersion,
      sequence: ++this.state.sequence, published_at: nowISO(), source_plugin: this.manifest.id,
    };
    this.state.publications.push(publication);
    const delivery = this.#emitEvent(normalized, publication.payload, schemaVersion);
    const result = { matched: delivery.matched, enqueued: delivery.delivered, dropped: 0, rejected: delivery.rejected };
    if (delivery.persisted) result.persisted = delivery.persisted;
    return result;
  }

  #eventDeadLetters(options = {}) {
    this.#requirePermission('event', 'events.deadLetters');
    const limit = Number(options && options.limit != null ? options.limit : 50);
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('events.deadLetters limit must be between 1 and 100');
    return [...this.state.eventDeliveries.values()].filter((item) => item.status === 'dead').slice(-limit).reverse().map(cloneJSON);
  }

  #eventRetry(deliveryID) {
    this.#requirePermission('event', 'events.retry');
    const id = String(deliveryID || '').trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(id)) throw new Error('events.retry delivery id is invalid');
    const item = this.state.eventDeliveries.get(id);
    if (!item || item.status !== 'dead') throw new Error(`events.retry delivery ${id} is not dead-lettered`);
    item.status = 'pending';
    item.attempts = 0;
    item.last_error = '';
    item.updated_at = nowISO();
    return cloneJSON(item);
  }

  #eventDiscard(deliveryID) {
    this.#requirePermission('event', 'events.discard');
    const id = String(deliveryID || '').trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(id)) throw new Error('events.discard delivery id is invalid');
    return this.state.eventDeliveries.delete(id);
  }

  #log(level, values) {
    this.state.logs.push({ level, message: values.map((value) => typeof value === 'string' ? value : JSON.stringify(value)).join(' '), at: nowISO(), worker: this.workerName || '' });
  }

  #metricName(value) {
    const name = typeof value === 'string' ? value.trim() : '';
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(name)) throw new Error('metric name is invalid');
    return name;
  }

  #metricLabels(value) {
    if (value == null) return {};
    if (typeof value !== 'object' || Array.isArray(value) || Object.prototype.toString.call(value) !== '[object Object]') {
      throw new Error('metric labels must be a plain object');
    }
    const entries = Object.entries(value);
    if (entries.length > 8) throw new Error('metric labels exceed the limit of 8');
    const labels = {};
    for (const [key, label] of entries) {
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,31}$/.test(key)) throw new Error(`metric label name ${key} is invalid`);
      if (typeof label !== 'string' || Buffer.byteLength(label, 'utf8') > 128) throw new Error(`metric label ${key} must be a string of at most 128 bytes`);
      labels[key] = label;
    }
    return labels;
  }

  #metricKey(name, labels) {
    return `${name}\0${JSON.stringify(Object.entries(labels).sort(([left], [right]) => left.localeCompare(right)))}`;
  }

  #metricSet(type, nameValue, value, labelsValue, add) {
    this.#requirePermission('metrics', `metrics.${type}`);
    const name = this.#metricName(nameValue);
    const labels = this.#metricLabels(labelsValue);
    const number = Number(value);
    if (typeof value !== 'number' || !Number.isFinite(number)) throw new Error('metric value must be a finite number');
    if (type === 'counter' && number < 0) throw new Error('metric counter delta must not be negative');
    const key = this.#metricKey(name, labels);
    const existing = this.state.metrics.get(key);
    if (existing && existing.type !== type) throw new Error(`metric ${name} with these labels is already a ${existing.type}`);
    if (!existing) {
      if (this.state.metrics.size >= 256) throw new Error('metric series limit reached: 256');
      const names = new Set([...this.state.metrics.values()].map((metric) => metric.name));
      if (!names.has(name) && names.size >= 64) throw new Error('metric name limit reached: 64');
    }
    const next = add ? (existing ? existing.value : 0) + number : number;
    if (!Number.isFinite(next)) throw new Error('metric value overflow');
    this.state.metrics.set(key, { name, type, value: next, labels, updated_at: nowISO() });
    return next;
  }

  #metricCounter(name, delta, labels, argumentCount) {
    if (argumentCount < 2 || delta == null) return this.#metricSet('counter', name, 1, {}, true);
    if (typeof delta === 'object' && !Array.isArray(delta)) return this.#metricSet('counter', name, 1, delta, true);
    return this.#metricSet('counter', name, delta, labels || {}, true);
  }

  #metricGauge(name, value, labels) {
    return this.#metricSet('gauge', name, value, labels || {}, false);
  }

  #metricDelete(nameValue, labelsValue, labelsProvided) {
    this.#requirePermission('metrics', 'metrics.delete');
    const name = this.#metricName(nameValue);
    if (labelsProvided) return this.state.metrics.delete(this.#metricKey(name, this.#metricLabels(labelsValue))) ? 1 : 0;
    let deleted = 0;
    for (const [key, metric] of this.state.metrics) {
      if (metric.name === name) {
        this.state.metrics.delete(key);
        deleted++;
      }
    }
    return deleted;
  }

  #metricClear() {
    this.#requirePermission('metrics', 'metrics.clear');
    const count = this.state.metrics.size;
    this.state.metrics.clear();
    return count;
  }

  #metricList() {
    this.#requirePermission('metrics', 'metrics.list');
    return cloneJSON([...this.state.metrics.values()].sort((left, right) => this.#metricKey(left.name, left.labels).localeCompare(this.#metricKey(right.name, right.labels))));
  }

  #context(kind, extra = {}) {
    return Object.assign({
      kind,
      plugin: { id: this.manifest.id, name: this.manifest.name || this.manifest.id, version: this.manifest.version || '0.0.0' },
      host: {
        runtime_version: API_CONTRACT.runtime.runtime_version,
        control_api_abi: API_CONTRACT.runtime.control_api_abi,
        tc_pipeline_abi: API_CONTRACT.runtime.tc_pipeline_abi,
        os: process.platform,
        arch: process.arch,
        features: API_CONTRACT.runtime.features.slice(),
        available_features: API_CONTRACT.runtime.features.slice(),
        feature_status: Object.fromEntries(API_CONTRACT.runtime.features.map((feature) => [feature, {available: true}])),
        resource_limits: cloneJSON(API_CONTRACT.runtime.resource_limits),
      },
    }, cloneJSON(extra));
  }

  run(handler, context = {}, optional = true) {
    this.load();
    const name = handlerName(handler, 'handler');
    const fn = this.exports[name];
    if (typeof fn !== 'function') {
      if (optional) return undefined;
      throw new Error(`control script does not export ${name}`);
    }
    this.context.__veerTestHandler = fn;
    this.context.__veerTestContext = cloneJSON(context);
    let result;
    try {
      result = vm.runInContext('__veerTestHandler(__veerTestContext)', this.context, { timeout: this.timeoutMs, displayErrors: true });
    } finally {
      delete this.context.__veerTestHandler;
      delete this.context.__veerTestContext;
    }
    if (result && typeof result.then === 'function') throw new Error('Veer control handlers must be synchronous');
    return cloneJSON(result);
  }

  reconcile(extra = {}) {
    return this.run('onReconcile', this.#context('reconcile', extra));
  }

  action(actionID, payload = {}) {
    const id = token(actionID, 'action');
    const contract = this.actionContracts.get(id);
    if (!contract) throw new Error(`action ${id} is not registered`);
    return this.run('onAction', this.#context('action', { action: {
      id, runtime_update: contract.runtime_update,
      request_schema_version: contract.request_schema_version,
      response_schema_version: contract.response_schema_version,
    }, payload }));
  }

	migrateEBPFState(request, options = {}) {
		this.load();
		if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error('eBPF state migration request is required');
		const objectID = token(request.object_id || request.object, 'migration object');
		const sourceMap = token(request.source_map, 'migration source map');
		const targetMap = token(request.target_map, 'migration target map');
		if (sourceMap === targetMap) throw new Error('migration source and target maps must differ');
		const object = this.surface.objects.find((item) => item.id === objectID);
		if (!object) throw new Error(`migration object ${objectID} is not registered`);
		const contracts = new Map((object.state_maps || []).map((item) => [item.name, item]));
		const source = contracts.get(sourceMap);
		const target = contracts.get(targetMap);
		if (!source || source.policy !== 'preserve') throw new Error(`migration source map ${sourceMap} must use preserve policy`);
		if (!target || target.policy !== 'migrate' || target.migrate_from !== sourceMap) {
			throw new Error(`migration target map ${targetMap} must migrate from ${sourceMap}`);
		}
		const fromVersion = Number(request.from_schema_version || source.schema_version);
		const toVersion = Number(request.to_schema_version || target.schema_version);
		if (!Number.isInteger(fromVersion) || !Number.isInteger(toVersion) || fromVersion !== source.schema_version || toVersion !== target.schema_version) {
			throw new Error('migration schema versions do not match the registered state map contracts');
		}
		const maxBatches = options.max_batches == null ? 65536 : Number(options.max_batches);
		if (!Number.isInteger(maxBatches) || maxBatches < 1 || maxBatches > 65536) throw new Error('migration max_batches must be between 1 and 65536');
		let cursor = '';
		let processed = 0;
		for (let batch = 1; batch <= maxBatches; batch++) {
			const result = this.run('onEBPFStateMigrate', this.#context('ebpf_state_migrate', {ebpf_migration: {
				protocol_version: 1,
				object_id: objectID,
				source_map: sourceMap,
				target_map: targetMap,
				from_schema_version: fromVersion,
				to_schema_version: toVersion,
				batch,
				cursor,
				max_entries: 256,
				max_bytes: 1 << 20,
			}}), false);
			if (!result || typeof result !== 'object' || Array.isArray(result) || typeof result.done !== 'boolean') {
				throw new Error(`eBPF state migration batch ${batch} must return progress with done`);
			}
			const batchProcessed = Number(result.processed);
			if (!Number.isInteger(batchProcessed) || batchProcessed < 0 || batchProcessed > 256) {
				throw new Error(`eBPF state migration batch ${batch} processed must be between 0 and 256`);
			}
			const nextCursor = String(result.cursor || '').trim().toLowerCase();
			if (nextCursor && (nextCursor.length % 2 !== 0 || !/^[0-9a-f]+$/.test(nextCursor))) {
				throw new Error(`eBPF state migration batch ${batch} cursor must be even-length hex`);
			}
			processed += batchProcessed;
			if (result.done) {
				if (nextCursor) throw new Error(`eBPF state migration batch ${batch} completed with a non-empty cursor`);
				return {status: 'completed', batches: batch, processed};
			}
			if (!nextCursor || batchProcessed === 0 || nextCursor === cursor) {
				throw new Error(`eBPF state migration batch ${batch} made no progress`);
			}
			cursor = nextCursor;
		}
		throw new Error(`eBPF state migration exceeded ${maxBatches} batches`);
	}

  fireTimer(name) {
    const id = token(name, 'timer');
    const timer = this.state.timers.get(id);
    if (!timer) throw new Error(`timer ${id} is not registered`);
    if (timer.kind === 'timeout') this.state.timers.delete(id);
    else timer.next_fire = new Date(Date.now() + timer.delay_ms).toISOString();
    return this.run('onTimer', this.#context('timer', { timer: Object.assign({}, cloneJSON(timer), { fired_at: nowISO() }) }));
  }

  emit(topic, payload = {}, options = {}) {
    this.load();
    const normalized = eventTopic(topic, 'event topic');
    const schemaVersion = eventSchemaVersion(options && options.schema_version, 'emit');
    return this.#emitEvent(normalized, payload, schemaVersion).delivered;
  }

  #emitEvent(normalized, payload, schemaVersion) {
    let delivered = 0;
    let matchedCount = 0;
    let rejected = 0;
    let persisted = 0;
    for (const subscription of this.surface.event_subscriptions) {
      const matched = subscription.match === 'prefix' ? eventTopicWithinPrefix(normalized, subscription.topic) : normalized === subscription.topic;
      if (!matched) continue;
      const source = customEventSource(normalized) || 'veer';
      if (source !== 'veer' && source !== this.manifest.id) {
        const allowed = this.eventAccess.some((access) => access.plugin === source && access.topic_prefixes.some((prefix) => eventTopicWithinPrefix(normalized, prefix)));
        if (!allowed) continue;
      }
      matchedCount++;
      if (schemaVersion !== subscription.schema_version) {
        rejected++;
        continue;
      }
      const event = {
        topic: normalized, subscription: subscription.id, sequence: ++this.state.sequence, published_at: nowISO(),
        source_plugin: source, target_plugin: this.manifest.id, resource: '', schema_version: schemaVersion,
        delivery: subscription.delivery || 'volatile', payload: cloneJSON(payload),
      };
      if (subscription.delivery === 'durable') {
        event.delivery_id = crypto.randomBytes(16).toString('hex');
        event.attempt = 1;
        persisted++;
      }
      this.#worker(subscription.worker).run(subscription.handler, this.#context('event', { event }), false);
      delivered++;
    }
    return { matched: matchedCount, delivered, rejected, persisted };
  }

  ring(subscriptionID, values = []) {
    this.load();
    const id = token(subscriptionID, 'ring subscription');
    const subscription = this.surface.ring_subscriptions.find((item) => item.id === id);
    if (!subscription) throw new Error(`ring subscription ${id} is not registered`);
    if (!Array.isArray(values) || values.length > subscription.max_records) throw new Error('ring records are invalid');
    const records = values.map((value) => {
      const data = typeof value === 'string' ? value : String(value && value.data || '');
      if (!/^(?:[a-fA-F0-9]{2})*$/.test(data)) throw new Error('ring record data must be hexadecimal');
      return { data: data.toLowerCase(), size: data.length / 2, remaining: Number(value && value.remaining || 0) };
    });
    const bytes = records.reduce((sum, record) => sum + record.size, 0);
    if (bytes > subscription.max_bytes) throw new Error('ring records exceed max_bytes');
    const payload = {
      subscription: id, object: subscription.object, map: subscription.map, records, bytes,
      dropped_records: 0, remaining: records.length ? records[records.length - 1].remaining : 0,
      limit_reached: false, read_at: nowISO(),
    };
    this.state.ringDeliveries.push({ subscription: id, records: records.length, bytes, at: payload.read_at });
    return this.#workerCall(subscription.worker, subscription.handler, payload);
  }

  snapshot() {
    this.load();
    const resources = {};
    for (const [resourceID, records] of this.state.resources) resources[resourceID] = Object.fromEntries([...records].map(([key, value]) => [key, cloneJSON(value)]));
    return {
      manifest: cloneJSON(this.manifest), surface: cloneJSON(this.surface), resources,
      kv: Object.fromEntries([...this.state.kv].map(([key, value]) => [key, cloneJSON(value.data)])),
      secrets: Object.fromEntries([...this.state.secrets].map(([key]) => [key, '[REDACTED]'])),
      blobs: Object.fromEntries([...this.state.blobs].map(([key, value]) => [key, cloneJSON(value.info)])),
      timers: cloneJSON([...this.state.timers.values()]), calls: cloneJSON(this.state.calls), logs: cloneJSON(this.state.logs),
      publications: cloneJSON(this.state.publications), ring_deliveries: cloneJSON(this.state.ringDeliveries),
      event_deliveries: cloneJSON([...this.state.eventDeliveries.values()]),
	  operations: cloneJSON([...this.state.operations.values()]),
      metrics: cloneJSON([...this.state.metrics.values()]), workers: this.#workerListSafe(),
    };
  }

  #workerListSafe() {
    return [...this.state.workers.keys()].map((name) => ({ name, mode: 'worker' }));
  }
}

function createTestHost(options) {
  return new VeerPluginTestHost(options).load();
}

module.exports = { VeerPluginTestHost, createTestHost };
