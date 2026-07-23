/// <reference path="./methods.d.ts" />

export interface VeerPluginTestHostOptions {
  pluginDir: string;
  timeoutMs?: number;
  fixtures?: {
    kv?: Record<string, unknown>;
    secrets?: Record<string, unknown>;
    resources?: Record<string, Record<string, unknown | { data: unknown; enabled?: boolean; revision?: number; updated_at?: string }>>;
	maps?: Record<string, Record<string, Record<string, string>>>;
  };
  adapters?: Partial<VeerHostControlMethodMap>;
}

export interface VeerPluginTestSnapshot {
  manifest: Record<string, unknown>;
  surface: Record<string, unknown>;
  resources: Record<string, Record<string, unknown>>;
  kv: Record<string, unknown>;
  secrets: Record<string, '[REDACTED]'>;
  blobs: Record<string, {key: string; bytes: number; sha256: string; created_at: string; updated_at: string}>;
  timers: unknown[];
  calls: unknown[];
  logs: unknown[];
  publications: unknown[];
	operations: VeerOperation[];
  ring_deliveries: unknown[];
  metrics: unknown[];
  workers: unknown[];
}

export class VeerPluginTestHost {
  constructor(options: VeerPluginTestHostOptions);
  load(): this;
  run(handler: string, context?: Record<string, unknown>, optional?: boolean): unknown;
  reconcile(extra?: Record<string, unknown>): unknown;
  action(actionID: string, payload?: unknown): unknown;
	migrateEBPFState(request: {
		object_id: string;
		source_map: string;
		target_map: string;
		from_schema_version?: number;
		to_schema_version?: number;
	}, options?: {max_batches?: number}): {status: 'completed'; batches: number; processed: number};
  fireTimer(name: string): unknown;
  emit(topic: string, payload?: unknown, options?: { schema_version?: number }): number;
  ring(subscriptionID: string, records?: Array<string | { data: string; remaining?: number }>): unknown;
  snapshot(): VeerPluginTestSnapshot;
}

export function createTestHost(options: VeerPluginTestHostOptions): VeerPluginTestHost;
