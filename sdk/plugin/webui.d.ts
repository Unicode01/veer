export {};

declare global {
  interface VeerPluginUIRecord<T = unknown> {
    id?: number;
    key: string;
    data: T;
    enabled: boolean;
    revision: number;
    created_at?: string;
    updated_at?: string;
    runtime_status?: Record<string, unknown> | null;
    runtime_error?: string;
  }

  interface VeerPluginUIError extends Error {
    payload?: Record<string, unknown> | null;
    status?: number;
    runtime_status?: Record<string, unknown> | null;
    runtime_error?: string;
  }

  interface VeerPluginRecordPicker {
    element: HTMLElement;
    select: HTMLSelectElement;
    input: HTMLInputElement;
    value(): string;
    isNew(): boolean;
    keys(): string[];
    setKeys(values: string[], selected?: string, forceNew?: boolean): void;
    selectKey(key: string): void;
    resetNew(suggestedKey?: string): void;
    refreshLabels(): void;
    onChange(listener: (detail: { key: string; isNew: boolean }) => void): this;
  }

  interface VeerPluginCollectionColumn {
    key: string;
    label?: string | (() => string);
    placeholder?: string | (() => string);
    type?: string;
    min?: number | string;
    max?: number | string;
    step?: number | string;
    inputmode?: string;
    wide?: boolean;
  }

  interface VeerPluginCollectionEditor<T extends Record<string, unknown> = Record<string, unknown>> {
    element: HTMLElement;
    add(value?: Partial<T>): unknown;
    setValues(values: T[]): void;
    values(): T[];
    refreshLabels(): void;
    count(): number;
  }

  interface VeerPluginHostBridge {
    readonly pluginId: string;
    readonly locale: string;
    readonly classes: Record<string, string>;
    readonly resources: Array<{
      id: string;
      description: string;
      methods: string[];
      runtime_update: string;
      max_records: number;
      max_record_bytes: number;
      schema_version: number;
      schema: Record<string, unknown> | null;
      schema_digest: string;
    }>;
    readonly actions: Array<{
      id: string;
      description: string;
      runtime_update: string;
      max_payload_bytes: number;
      request_schema_version: number;
      request_schema: Record<string, unknown> | null;
      request_schema_digest: string;
      response_schema_version: number;
      response_schema: Record<string, unknown> | null;
      response_schema_digest: string;
    }>;
    readonly rpcLimits: {
      max_inflight: number;
      max_payload_bytes: number;
      max_pending_bytes: number;
    };
    h<K extends keyof HTMLElementTagNameMap>(tag: K, options?: {
      className?: string;
      text?: unknown;
      title?: string;
      attrs?: Record<string, string | number | boolean | null | undefined>;
    } | null, children?: Node | string | number | Array<Node | string | number | null | undefined>): HTMLElementTagNameMap[K];
    stack(children?: unknown, options?: Record<string, unknown>): HTMLElement;
    card(children?: unknown, options?: Record<string, unknown>): HTMLElement;
    button(text: string, onClick?: ((event: MouseEvent) => void) | null, secondary?: boolean): HTMLButtonElement;
    setButtonState(button: HTMLButtonElement, state?: {
      busy?: boolean;
      disabled?: boolean;
      hidden?: boolean;
      label?: string;
      title?: string;
      state?: string;
      tone?: 'danger' | string;
    }): HTMLButtonElement;
    badge(text: string, title?: string): HTMLElement;
    status(text: string): HTMLElement;
    stat(label: string, value: unknown, detail?: string): HTMLElement;
    table(headers: unknown[], rows: unknown[][]): HTMLTableElement;
    recordPicker(options?: Record<string, unknown>): VeerPluginRecordPicker;
    collectionEditor<T extends Record<string, unknown> = Record<string, unknown>>(options: {
      columns: VeerPluginCollectionColumn[];
      addLabel?: string | (() => string);
      emptyLabel?: string | (() => string);
      removeLabel?: string | (() => string);
      removeText?: string | (() => string);
    }): VeerPluginCollectionEditor<T>;
    t(messages: Record<string, Record<string, string>>, key: string, params?: Record<string, unknown>): string;
    onLocaleChange(callback: (locale: string) => void): () => void;
    toast(message: string, timeout?: number): HTMLElement;
    errorText(error: unknown, fallback?: string): string;
    toastError(error: unknown, timeout?: number): HTMLElement;
    confirm(options: {
      title?: string;
      message: string;
      confirmText?: string;
      cancelText?: string;
      danger?: boolean;
    }): Promise<boolean>;
    requestResize(): void;
    data: {
      list<T = unknown>(resource: string, options?: { limit?: number; offset?: number }): Promise<{ records: VeerPluginUIRecord<T>[]; runtime_status?: unknown }>;
      get<T = unknown>(resource: string, key: string): Promise<VeerPluginUIRecord<T>>;
      create<T = unknown>(resource: string, data: T, options?: { key?: string; enabled?: boolean }): Promise<VeerPluginUIRecord<T>>;
      update<T = unknown>(resource: string, key: string, data: T, options?: { enabled?: boolean }): Promise<VeerPluginUIRecord<T>>;
      upsert<T = unknown>(resource: string, key: string, data: T, options?: { enabled?: boolean }): Promise<VeerPluginUIRecord<T>>;
      delete(resource: string, key: string): Promise<unknown>;
    };
    plugins: {
      resources: {
        list<T = unknown>(plugin: string, resource: string, options?: { limit?: number; offset?: number }): Promise<{ records: VeerPluginUIRecord<T>[] }>;
        get<T = unknown>(plugin: string, resource: string, key: string): Promise<VeerPluginUIRecord<T>>;
      };
    };
    assets: {
      text(path: string): Promise<string>;
      json<T = unknown>(path: string): Promise<T>;
      style(path: string, options?: { media?: string }): Promise<HTMLStyleElement>;
      script(path: string): Promise<HTMLScriptElement>;
      dataURL(path: string): Promise<string>;
    };
    action<T = unknown>(name: string, payload?: unknown): Promise<T>;
  }

  interface Window {
    VeerPluginHost: VeerPluginHostBridge;
  }
}
