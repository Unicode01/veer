export {};

declare global {
  type VeerJSONPrimitive = string | number | boolean | null;
  type VeerJSONValue = VeerJSONPrimitive | VeerJSONValue[] | { [key: string]: VeerJSONValue };
  type VeerResourceMethod = 'list' | 'get' | 'create' | 'update' | 'delete';
  type VeerRuntimeUpdate = 'none' | 'manual' | 'plugin_reconcile' | 'runtime_apply' | 'runtime_query';

  interface VeerPluginHostInfo {
    runtime_version: string;
    control_api_abi: number;
    tc_pipeline_abi: number;
    os: string;
    arch: string;
    kernel_release: string;
    core_priority: number;
    features: string[];
    available_features: string[];
    feature_status: Record<string, { available: boolean; reason?: string }>;
    resource_limits: VeerPluginResourceLimits;
  }

  interface VeerPluginResourceLimits {
    objects_per_plugin: number;
    capabilities_per_plugin: number;
    programs_per_plugin: number;
    maps_per_plugin: number;
    hooks_per_plugin: number;
    resources_per_plugin: number;
    actions_per_plugin: number;
    services_per_plugin: number;
    virtual_interfaces_per_plugin: number;
    instructions_per_program: number;
    instructions_per_plugin: number;
    map_memory_bytes: number;
    plugin_map_memory_bytes: number;
    global_map_memory_bytes: number;
    plugin_database_bytes: number;
    global_database_bytes: number;
    blob_objects_per_plugin: number;
    blob_object_bytes: number;
    plugin_blob_bytes: number;
    global_blob_bytes: number;
    control_memory_bytes: number;
    global_control_memory_bytes: number;
    control_process_memory_bytes: number;
    control_pids: number;
    global_control_pids: number;
    control_cpu_percent: number;
  }

  interface VeerVirtualInterfaceSpec {
    id: string;
    type?: 'pipeline' | 'handoff' | string;
    description?: string;
  }

  interface VeerResourceSpec {
    id: string;
    description?: string;
    methods?: VeerResourceMethod[];
    control_methods?: VeerResourceMethod[];
    runtime_update?: VeerRuntimeUpdate;
    max_records?: number;
    max_record_bytes?: number;
    secret_fields?: string[];
    schema_version?: number;
    schema?: Record<string, VeerJSONValue>;
  }

  interface VeerActionSpec {
    id: string;
    description?: string;
    runtime_update?: VeerRuntimeUpdate;
    max_payload_bytes?: number;
    request_schema_version?: number;
    request_schema?: Record<string, VeerJSONValue>;
    request_schema_digest?: string;
    response_schema_version?: number;
    response_schema?: Record<string, VeerJSONValue>;
    response_schema_digest?: string;
  }

  interface VeerObjectProgramSpec {
    id: string;
    section: string;
    type?: 'tc' | 'xdp' | 'netfilter' | 'control' | string;
    attach_type?: string;
  }

  interface VeerObjectSpec {
    id: string;
    path?: string;
    sha256?: string;
    variants?: Array<{ architecture: string; path: string; sha256?: string }>;
    description?: string;
    programs?: VeerObjectProgramSpec[];
    state_maps?: Array<{
      name: string;
      policy: 'preserve' | 'migrate' | 'reset';
      schema_version?: number;
      migrate_from?: string;
    }>;
  }

  interface VeerHookSpec {
    id: string;
    engine?: 'tc' | 'xdp' | 'netfilter' | 'control' | string;
    attach?: 'ingress' | 'egress' | 'both' | 'none' | string;
    stage?: 'pre_forward' | 'post_lookup' | 'post_apply' | 'pre_reply' | 'post_reply' | 'post_reply_apply' | string;
    family?: 'inet' | 'ipv4' | 'ipv6';
    hook?: 'prerouting' | 'input' | 'forward' | 'output' | 'postrouting';
    phase?: 'early' | 'raw' | 'mangle' | 'dstnat' | 'filter' | 'security' | 'srcnat' | 'late';
    namespace?: 'host' | string;
    priority?: number;
    before?: string[];
    after?: string[];
    program?: string;
    mode?: string;
    context?: string[];
    interfaces?: string[];
    packet_metadata?: VeerPacketMetadataBinding[];
  }

  interface VeerPacketMetadataBinding {
    slot: number;
    namespace: `${string}/${string}`;
    schema_version?: number;
    max_bytes?: number;
    access?: 'read' | 'read_write';
  }

  interface VeerPipelineAttachSpec {
    id: string;
    direction: 'forward' | 'reply';
    phase?: 'around_core' | 'after_apply';
    attach?: 'ingress' | 'egress';
    priority: number;
    before?: string[];
    after?: string[];
    program: string;
    mode?: string;
    context?: string[];
    interfaces?: string[];
    packet_metadata?: VeerPacketMetadataBinding[];
  }

  interface VeerUIRegistration {
    static_dir: string;
    entry: string;
    sha256?: string;
    page: string;
    page_title: string;
    resources?: VeerUIResourceAccess[];
    actions?: string[];
    resource_access?: VeerUICrossPluginResourceAccess[];
  }

  interface VeerUIResourceAccess {
    resource: string;
    methods: VeerResourceMethod[];
  }

  interface VeerUICrossPluginResourceAccess {
    plugin: string;
    resource: string;
    methods: Array<'list' | 'get'>;
  }

  interface VeerPluginAPI {
    host(): VeerPluginHostInfo;
    capabilities(values: string[] | string, ...rest: string[]): void;
    resource(spec: VeerResourceSpec): void;
    action(spec: VeerActionSpec): void;
    service(spec: VeerServiceSpec): void;
    virtualInterface(spec: VeerVirtualInterfaceSpec): void;
    pipelineNode(spec: VeerVirtualInterfaceSpec): void;
    handoff(spec: VeerVirtualInterfaceSpec): void;
  }

  interface VeerServiceSpec {
    id: string;
    version: string;
    description?: string;
    actions?: string[];
    resources?: string[];
  }

  interface VeerServiceProvider {
    plugin_id: string;
    plugin_name: string;
    plugin_version: string;
    stability: string;
    service: VeerServiceSpec;
    actions?: VeerActionSpec[];
    resources?: VeerResourceSpec[];
  }

  interface VeerServiceQuery {
    service?: string;
    version?: string;
    provider?: string;
  }

  interface VeerServicesAPI {
    list(query?: VeerServiceQuery): VeerServiceProvider[];
    resolve(query: VeerServiceQuery & { service: string }): VeerServiceProvider;
    call<T extends VeerJSONValue = VeerJSONValue>(request: VeerServiceQuery & {
      service: string;
      action: string;
      payload?: VeerJSONValue;
    }): { status: string; plugin: string; action: string; service: string; service_version: string; runtime_update: VeerRuntimeUpdate; result?: T };
  }

  interface VeerResourceRecord<T extends VeerJSONValue = VeerJSONValue> {
    id?: number;
    key: string;
    data: T;
    enabled: boolean;
    revision: number;
    created_at?: string;
    updated_at?: string;
  }

  interface VeerListOptions { limit?: number; offset?: number; }

  interface VeerResourceTransactionOperation {
    op: 'set' | 'delete';
    plugin?: string;
    resource: string;
    key: string;
    data?: VeerJSONValue;
    enabled?: boolean;
  }

  interface VeerResourceTransactionResult {
    status: 'completed';
    operations: number;
    mutated_resources: number;
    applied: boolean;
  }

  interface VeerResourcesAPI {
    get<T extends VeerJSONValue = VeerJSONValue>(resource: string, key: string): VeerResourceRecord<T> | null;
    list<T extends VeerJSONValue = VeerJSONValue>(resource: string, options?: VeerListOptions): VeerResourceRecord<T>[];
    set(resource: string, key: string, data: VeerJSONValue, enabled?: boolean, apply?: boolean): void;
    delete(resource: string, key: string, apply?: boolean): void;
    transaction(operations: VeerResourceTransactionOperation[], options?: { apply?: boolean }): VeerResourceTransactionResult;
  }

  interface VeerCrossPluginResourcesAPI {
    get<T extends VeerJSONValue = VeerJSONValue>(plugin: string, resource: string, key: string): VeerResourceRecord<T> | null;
    list<T extends VeerJSONValue = VeerJSONValue>(plugin: string, resource: string, options?: VeerListOptions): VeerResourceRecord<T>[];
    set(plugin: string, resource: string, key: string, data: VeerJSONValue, enabled?: boolean, apply?: boolean): VeerResourceRecord;
    delete(plugin: string, resource: string, key: string, apply?: boolean): { status: string };
    transaction(operations: VeerResourceTransactionOperation[], options?: { apply?: boolean }): VeerResourceTransactionResult;
  }

  interface VeerKVAPI {
    get<T extends VeerJSONValue = VeerJSONValue>(key: string): VeerResourceRecord<T> | null;
    set(key: string, value: VeerJSONValue): void;
    delete(key: string): void;
    list<T extends VeerJSONValue = VeerJSONValue>(options?: VeerListOptions): VeerResourceRecord<T>[];
  }

  interface VeerSecretAPI {
    get<T extends VeerJSONValue = VeerJSONValue>(key: string): T | null;
    set(key: string, value: VeerJSONValue): void;
    delete(key: string): void;
  }

  interface VeerBlobInfo {
    key: string;
    bytes: number;
    sha256: string;
    created_at: string;
    updated_at: string;
  }

  interface VeerBlobUploadInfo {
    upload_id: string;
    key: string;
    bytes: number;
    expected_bytes?: number;
    expected_sha256?: string;
    created_at: string;
  }

  interface VeerBlobAPI {
    begin(request: {key: string; expected_bytes?: number; sha256?: string; expected_sha256?: string}): VeerBlobUploadInfo;
    write(request: {upload_id: string; offset: number; payload_hex: string}): VeerBlobUploadInfo;
    commit(request: {upload_id: string}): VeerBlobInfo;
    abort(request: {upload_id: string}): {aborted: boolean};
    put(request: {key: string; payload_hex: string; sha256?: string; expected_sha256?: string}): VeerBlobInfo;
    read(request: {key: string; offset?: number; max_bytes?: number}): {blob: VeerBlobInfo; offset: number; payload_hex: string; bytes: number; eof: boolean} | null;
    stat(request: {key: string}): VeerBlobInfo | null;
    list(request?: {after?: string; limit?: number}): VeerBlobInfo[];
    delete(request: {key: string}): {deleted: boolean};
    verify(request: {key: string}): {verified: true; blob: VeerBlobInfo};
  }

  interface VeerTimerState {
    name: string;
    kind: 'timeout' | 'interval';
    delay_ms: number;
    payload: VeerJSONValue;
    next_fire: string;
  }

  interface VeerTimerAPI {
    setTimeout(name: string, delayMs: number, payload?: VeerJSONValue): void;
    setInterval(name: string, delayMs: number, payload?: VeerJSONValue): void;
    clear(name: string): void;
    list(): VeerTimerState[];
  }

  type VeerOperationStatus = 'pending' | 'running' | 'retry_wait' | 'completed' | 'failed' | 'cancelled';

  interface VeerOperation<TInput extends VeerJSONValue = VeerJSONValue, TState extends VeerJSONValue = VeerJSONValue, TResult extends VeerJSONValue = VeerJSONValue> {
    id: string;
    key: string;
    kind: string;
    status: VeerOperationStatus;
    phase: string;
    input: TInput | null;
    state: TState | null;
    result: TResult | null;
    error: string | null;
    attempts: number;
    revision: number;
    next_attempt_unix_ms: number;
    resumable: boolean;
    created_at: string;
    updated_at: string;
  }

  interface VeerOperationsAPI {
    begin<TInput extends VeerJSONValue = VeerJSONValue, TState extends VeerJSONValue = VeerJSONValue>(request: {
      key: string;
      kind: string;
      input?: TInput;
      state?: TState;
      restart?: boolean;
    }): VeerOperation<TInput, TState>;
    get<TInput extends VeerJSONValue = VeerJSONValue, TState extends VeerJSONValue = VeerJSONValue, TResult extends VeerJSONValue = VeerJSONValue>(id: string): VeerOperation<TInput, TState, TResult> | null;
    getByKey<TInput extends VeerJSONValue = VeerJSONValue, TState extends VeerJSONValue = VeerJSONValue, TResult extends VeerJSONValue = VeerJSONValue>(key: string): VeerOperation<TInput, TState, TResult> | null;
    list(options?: {kind?: string; status?: VeerOperationStatus; resumable?: boolean; limit?: number}): VeerOperation[];
    claim(id: string, expectedRevision: number): VeerOperation;
    checkpoint<TState extends VeerJSONValue = VeerJSONValue>(id: string, expectedRevision: number, update: {phase?: string; state: TState}): VeerOperation<VeerJSONValue, TState>;
    complete<TResult extends VeerJSONValue = VeerJSONValue>(id: string, expectedRevision: number, result?: TResult): VeerOperation<VeerJSONValue, VeerJSONValue, TResult>;
    retry<TState extends VeerJSONValue = VeerJSONValue>(id: string, expectedRevision: number, update: {phase?: string; state?: TState; error: string; delay_ms?: number}): VeerOperation<VeerJSONValue, TState>;
    fail<TState extends VeerJSONValue = VeerJSONValue>(id: string, expectedRevision: number, update: {phase?: string; state?: TState; error: string}): VeerOperation<VeerJSONValue, TState>;
    cancel<TState extends VeerJSONValue = VeerJSONValue>(id: string, expectedRevision: number, update?: {phase?: string; state?: TState; error?: string}): VeerOperation<VeerJSONValue, TState>;
    remove(id: string): void;
    stats(): {total: number; by_status: Partial<Record<VeerOperationStatus, number>>; bytes: number; record_limit: number; byte_limit: number};
  }

  interface VeerWorkerState {
    name: string;
    mode: 'worker';
    executing: boolean;
    queue_depth: number;
    pending_requests: number;
    pending_bytes: number;
  }

  interface VeerWorkerAPI {
    call<T extends VeerJSONValue = VeerJSONValue>(name: string, handler: string, payload?: VeerJSONValue): T;
    dispatch(name: string, handler: string, payload?: VeerJSONValue): { queued: true; worker: string; handler: string };
    list(): VeerWorkerState[];
    stats(): Record<string, number>;
  }

  interface VeerEventSubscriptionSpec {
    id: string;
    topic: string;
    match?: 'exact' | 'prefix';
    worker?: string;
    handler?: string;
    queue_size?: number;
    delivery?: 'volatile' | 'durable';
    max_attempts?: number;
    retry_delay_ms?: number;
    schema_version?: number;
    schema?: Record<string, VeerJSONValue>;
    schema_digest?: string;
  }

  interface VeerEventsAPI {
    subscribe(spec: VeerEventSubscriptionSpec): void;
    publish(topic: string, payload?: VeerJSONValue, options?: { schema_version?: number }): {
      matched: number;
      enqueued: number;
      persisted?: number;
      deferred?: number;
      dropped: number;
      rejected: number;
    };
    stats(): Record<string, VeerJSONValue>;
    deadLetters(options?: { limit?: number }): VeerEventDelivery[];
    retry(deliveryId: string): VeerEventDelivery;
    discard(deliveryId: string): boolean;
  }

  interface VeerEventDelivery {
    delivery_id: string;
    subscription: string;
    topic: string;
    sequence: number;
    published_at: string;
    source_plugin: string;
    target_plugin: string;
    resource: string;
    schema_version: number;
    payload: VeerJSONValue;
    attempts: number;
    max_attempts: number;
    status: 'pending' | 'dead';
    last_error: string;
    created_at: string;
    updated_at: string;
  }

  type VeerMetricLabels = Record<string, string>;

  interface VeerMetricState {
    name: string;
    type: 'counter' | 'gauge';
    value: number;
    labels?: VeerMetricLabels;
    updated_at?: string;
  }

  interface VeerMetricsAPI {
    counter(name: string, labels?: VeerMetricLabels): number;
    counter(name: string, delta: number, labels?: VeerMetricLabels): number;
    gauge(name: string, value: number, labels?: VeerMetricLabels): number;
    delete(name: string, labels?: VeerMetricLabels): number;
    clear(): number;
    list(): VeerMetricState[];
  }

  interface VeerCryptoAPI {
    md5(...values: (string | number[])[]): string;
    randomBytes(length: number): string;
    sha256File(relativePath: string): string;
  }

  interface Crypto extends VeerCryptoAPI {}

  interface VeerNetRequest {
    namespace?: string;
    netns?: string;
  }

  type VeerNetNamespaceSelector = string | { namespace?: string; netns?: string };
  type VeerNetEtherType = number | string;

  interface VeerNetL2SendRequest extends VeerNetRequest {
    interface: string;
    ethertype: VeerNetEtherType;
    dst_mac: string;
    src_mac?: string;
    payload?: string;
  }

  interface VeerNetL2RecvRequest extends VeerNetRequest {
    interface: string;
    ethertype: VeerNetEtherType;
    timeout_ms?: number;
    max_bytes?: number;
    recv_src_mac?: string;
    recv_dst_mac?: string;
    pppoe_code?: number;
    pppoe_session_id?: number;
  }

  interface VeerNetL2RecvManyRequest extends VeerNetL2RecvRequest {
    max_frames?: number;
    idle_timeout_ms?: number;
  }

  interface VeerNetL2ExchangeRequest extends VeerNetL2SendRequest {
    recv_ethertype?: VeerNetEtherType;
    timeout_ms?: number;
    max_bytes?: number;
    recv_src_mac?: string;
    recv_dst_mac?: string;
    pppoe_code?: number;
    pppoe_session_id?: number;
  }

  interface VeerNetL2ExchangeManyRequest extends VeerNetL2ExchangeRequest {
    max_frames?: number;
    idle_timeout_ms?: number;
  }

  interface VeerNetL2Frame {
    namespace: string;
    interface: string;
    ifindex: number;
    ethertype: string;
    dst_mac: string;
    src_mac: string;
    payload_hex: string;
    frame_hex: string;
  }

  interface VeerNetL2API {
    send(request: VeerNetL2SendRequest): void;
    recv(request: VeerNetL2RecvRequest): VeerNetL2Frame | null;
    recvMany(request: VeerNetL2RecvManyRequest): VeerNetL2Frame[];
    exchange(request: VeerNetL2ExchangeRequest): VeerNetL2Frame | null;
    exchangeMany(request: VeerNetL2ExchangeManyRequest): VeerNetL2Frame[];
  }

  interface VeerNetUDPSendRequest extends VeerNetRequest {
    interface: string;
    remote_ip: string;
    remote_port: number;
    local_ip?: string;
    local_port?: number;
    payload?: string;
    payload_hex?: string;
    timeout_ms?: number;
  }

  interface VeerNetUDPRecvRequest extends VeerNetRequest {
    interface: string;
    local_port: number;
    local_ip?: string;
    remote_ip?: string;
    remote_port?: number;
    timeout_ms?: number;
    max_bytes?: number;
  }

  interface VeerNetUDPExchangeRequest extends VeerNetUDPSendRequest {
    max_bytes?: number;
  }

  interface VeerNetUDPResult {
    namespace: string;
    interface: string;
    bytes: number;
    local_ip?: string;
    local_port?: number;
    local_addr?: string;
    remote_ip?: string;
    remote_port?: number;
    remote_addr?: string;
  }

  interface VeerNetUDPDatagram extends VeerNetUDPResult {
    payload_hex: string;
  }

  interface VeerNetUDPAPI {
    send(request: VeerNetUDPSendRequest): VeerNetUDPResult;
    recv(request: VeerNetUDPRecvRequest): VeerNetUDPDatagram | null;
    exchange(request: VeerNetUDPExchangeRequest): VeerNetUDPDatagram | null;
  }

  interface VeerNetLinkStatistics {
    rx_packets: number;
    tx_packets: number;
    rx_bytes: number;
    tx_bytes: number;
    rx_errors: number;
    tx_errors: number;
    rx_dropped: number;
    tx_dropped: number;
  }

  interface VeerNetLinkInfo {
    namespace: string;
    name: string;
    created: boolean;
    ifindex: number;
    kind: string;
    parent: string;
    mtu: number;
    mac: string;
    up: boolean;
    arp: boolean;
    oper_state: string;
    addresses: string[];
    peer_name: string;
    peer_ifindex: number;
    master_name: string;
    master_ifindex: number;
    promiscuous: boolean;
    gso_max_size: number;
    gso_max_segs: number;
    vlan_id: number;
    vlan_protocol: string;
    vrf_table: number;
    statistics?: VeerNetLinkStatistics;
  }

  interface VeerNetLinkEnsureRequest extends VeerNetRequest {
    name: string;
    mtu?: number;
    up?: boolean;
  }

  interface VeerNetVethRequest extends VeerNetRequest {
    host: string;
    peer: string;
    mtu?: number;
    up?: boolean;
  }

  interface VeerNetMacvlanRequest extends VeerNetLinkEnsureRequest {
    parent: string;
    mode?: 'bridge' | 'private' | 'vepa' | 'passthru';
    mac?: string;
  }

  interface VeerNetVLANRequest extends VeerNetLinkEnsureRequest {
    parent: string;
    vlan_id: number;
    protocol?: '802.1q' | '802.1ad';
  }

  interface VeerNetVRFRequest extends VeerNetRequest {
    name: string;
    table: number;
    up?: boolean;
  }

  interface VeerNetMasterRequest extends VeerNetRequest {
    link: string;
    master: string;
    up?: boolean;
  }

  interface VeerNetLinkEnsureResult {
    link: VeerNetLinkInfo;
    created: boolean;
  }

  interface VeerNetVethResult {
    host: VeerNetLinkInfo;
    peer: VeerNetLinkInfo;
    created: boolean;
  }

  interface VeerNetOwnedLink {
    name: string;
    namespace: string;
    key: string;
    type: string;
    metadata: Record<string, VeerJSONValue>;
    created_at: string;
    updated_at: string;
  }

  type VeerNetOffloadFeature = 'rx' | 'tx' | 'sg' | 'tso' | 'ufo' | 'gso' | 'gro' | 'lro';
  type VeerNetOffloadState = Partial<Record<VeerNetOffloadFeature, boolean>>;

  interface VeerNetGSOLimits {
    max_size: number;
    max_segs: number;
  }

  interface VeerNetLinkAPI {
    get(name: string, namespace?: VeerNetNamespaceSelector): VeerNetLinkInfo;
    list(namespace?: VeerNetNamespaceSelector): VeerNetLinkInfo[];
    ensureBridge(request: VeerNetLinkEnsureRequest): VeerNetLinkInfo;
    ensureVeth(request: VeerNetVethRequest): VeerNetVethResult;
    ensureDummy(request: VeerNetLinkEnsureRequest): VeerNetLinkEnsureResult;
    ensureMacvlan(request: VeerNetMacvlanRequest): VeerNetLinkEnsureResult;
    ensureVLAN(request: VeerNetVLANRequest): VeerNetLinkEnsureResult;
    ensureVRF(request: VeerNetVRFRequest): VeerNetLinkEnsureResult;
    delete(name: string, namespace?: VeerNetNamespaceSelector): void;
    release(name: string, namespace?: VeerNetNamespaceSelector): void;
    owned(): VeerNetOwnedLink[];
    setMaster(request: VeerNetMasterRequest): VeerNetLinkInfo;
    clearMaster(name: string, namespace?: VeerNetNamespaceSelector): VeerNetLinkInfo;
    setUp(name: string, up?: boolean, namespace?: VeerNetNamespaceSelector): void;
    setMTU(name: string, mtu: number, namespace?: VeerNetNamespaceSelector): void;
    setARP(name: string, enabled: boolean, namespace?: VeerNetNamespaceSelector): VeerNetLinkInfo;
    setPromiscuous(name: string, enabled: boolean, namespace?: VeerNetNamespaceSelector): VeerNetLinkInfo;
    getOffloads(name: string, namespace?: VeerNetNamespaceSelector): VeerNetOffloadState;
    setOffloads(name: string, features: VeerNetOffloadState, namespace?: VeerNetNamespaceSelector): void;
    setGSO(name: string, limits: VeerNetGSOLimits, namespace?: VeerNetNamespaceSelector): VeerNetLinkInfo;
  }

  interface VeerNetAddrRequest extends VeerNetRequest {
    interface: string;
    cidr: string;
  }

  interface VeerNetAddrAPI {
    replace(request: VeerNetAddrRequest): void;
    delete(request: VeerNetAddrRequest): void;
  }

  interface VeerNetRouteNexthop extends VeerNetRequest {
    dev: string;
    gateway?: string;
    weight?: number;
    onlink?: boolean;
  }

  interface VeerNetRouteRequest extends VeerNetRequest {
    dst: string;
    dev?: string;
    gateway?: string;
    src?: string;
    table?: number;
    metric?: number;
    scope?: number;
    nexthops?: VeerNetRouteNexthop[];
  }

  interface VeerNetRuleRequest extends VeerNetRequest {
    family?: 'ipv4' | 'ipv6' | '4' | '6' | 'inet' | 'inet6';
    priority: number;
    table: number;
    src?: string;
    dst?: string;
    mark?: number;
    mask?: number;
    iif?: string;
    oif?: string;
    invert?: boolean;
  }

  interface VeerNetNeighRequest extends VeerNetRequest {
    interface: string;
    ip: string;
    mac?: string;
    state?: 'permanent' | 'noarp';
    vlan?: number;
  }

  interface VeerNetTransactionOperation<T extends VeerNetRequest = VeerNetRequest> {
    op: 'replace' | 'delete';
    request: T;
  }

  interface VeerNetTransactionResult {
    status: 'completed';
    operations: number;
  }

  interface VeerNetNamespaceInfo {
    name: string;
    identity: string;
    created?: boolean;
    owned?: boolean;
  }

  interface VeerNetTunTapInfo {
    name: string;
    namespace: string;
    mode: 'tun' | 'tap';
    ifindex: number;
    mtu: number;
    up: boolean;
    mac?: string;
    reads: number;
    read_bytes: number;
    writes: number;
    write_bytes: number;
    read_errors: number;
    write_errors: number;
  }

  interface VeerNetTunTapRequest {
    name: string;
    namespace?: string;
    mode?: 'tun' | 'tap';
    mtu?: number;
    up?: boolean;
  }

  interface VeerNetHTTPRequest extends VeerNetRequest {
    url: string;
    method?: 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';
    interface: string;
    headers?: Record<string, string>;
    body_text?: string;
    body_hex?: string;
    source_ip?: string;
    resolver_ip?: string;
    resolver_port?: number;
    dns_transport?: 'udp' | 'tcp';
    timeout_ms?: number;
    max_response_bytes?: number;
    follow_redirects?: boolean;
    max_redirects?: number;
    server_name?: string;
    ca_pem?: string;
    client_cert_pem?: string;
    client_key_pem?: string;
  }

  interface VeerNetHTTPResponse {
    status_code: number;
    status: string;
    headers: Record<string, string[]>;
    body_hex: string;
    body_text?: string;
    bytes: number;
    final_url: string;
  }

  type VeerNetDNSRecord = string | {
    host: string;
    preference: number;
  } | {
    target: string;
    port: number;
    priority: number;
    weight: number;
  };

  interface VeerNetDNSRequest extends VeerNetRequest {
    name: string;
    type?: 'ip' | 'a' | 'aaaa' | 'txt' | 'mx' | 'srv' | 'cname' | 'ptr';
    interface: string;
    service?: string;
    protocol?: string;
    source_ip?: string;
    resolver_ip?: string;
    resolver_port?: number;
    transport?: 'udp' | 'tcp';
    timeout_ms?: number;
  }

  interface VeerNetDNSResponse {
    name: string;
    type: 'ip' | 'a' | 'aaaa' | 'txt' | 'mx' | 'srv' | 'cname' | 'ptr';
    records: VeerNetDNSRecord[];
  }

  type VeerNetSocketNetwork = 'tcp' | 'tcp4' | 'tcp6' | 'udp' | 'udp4' | 'udp6';

  interface VeerNetSocketWatchInfo {
    worker: string;
    handler: string;
    max_bytes: number;
    events: number;
    rejected: number;
    last_event_at?: string;
    last_error?: string;
  }

  interface VeerNetSocketInfo {
    handle: string;
    network: VeerNetSocketNetwork;
    kind: 'connection' | 'listener' | 'datagram';
    namespace: string;
    interface: string;
    state: 'open' | 'listening' | 'eof';
    parent_handle?: string;
    local_addr?: string;
    local_ip?: string;
    local_port?: number;
    remote_addr?: string;
    remote_ip?: string;
    remote_port?: number;
    bytes_read: number;
    bytes_written: number;
    created_at: string;
    last_read_at?: string;
    last_write_at?: string;
    last_error?: string;
    watch?: VeerNetSocketWatchInfo;
  }

  interface VeerNetSocketOpenRequest extends VeerNetRequest {
    network: VeerNetSocketNetwork;
    interface: string;
    remote_ip: string;
    remote_port: number;
    local_ip?: string;
    local_port?: number;
    timeout_ms?: number;
    keepalive_ms?: number;
    no_delay?: boolean;
  }

  interface VeerNetSocketListenRequest extends VeerNetRequest {
    network: VeerNetSocketNetwork;
    interface: string;
    local_port: number;
    local_ip?: string;
    keepalive_ms?: number;
    no_delay?: boolean;
  }

  interface VeerNetSocketEvent {
    type: 'data' | 'accept' | 'eof' | 'error';
    occurred_at: string;
    socket: VeerNetSocketInfo;
    accepted?: VeerNetSocketInfo;
    payload_hex?: string;
    bytes?: number;
    remote_addr?: string;
    remote_ip?: string;
    remote_port?: number;
    error?: string;
  }

  interface VeerNetSocketAPI {
    open(request: VeerNetSocketOpenRequest): VeerNetSocketInfo;
    listen(request: VeerNetSocketListenRequest): VeerNetSocketInfo;
    accept(request: { handle: string; timeout_ms?: number }): VeerNetSocketInfo | { timeout: true };
    read(request: { handle: string; max_bytes?: number; timeout_ms?: number }): {
      payload_hex: string; bytes: number; timeout: boolean; eof: boolean;
      remote_addr?: string; remote_ip?: string; remote_port?: number;
    };
    write(request: { handle: string; payload_hex: string; timeout_ms?: number; remote_ip?: string; remote_port?: number }): { bytes: number };
    close(request: { handle: string }): { closed: boolean };
    status(request: { handle: string }): VeerNetSocketInfo;
    list(): VeerNetSocketInfo[];
    watch(request: { handle: string; worker: string; handler: string; max_bytes?: number }): VeerNetSocketWatchInfo;
    unwatch(request: { handle: string }): { stopped: boolean };
    watchList(): Array<{ handle: string; watch: VeerNetSocketWatchInfo }>;
  }

  interface VeerNetMutationAPI<T extends VeerNetRequest = VeerNetRequest> {
    replace(request: T): void;
    delete(request: T): void;
    transaction(operations: VeerNetTransactionOperation<T>[]): VeerNetTransactionResult;
  }

  interface VeerNetAPI {
    prefix: { subnet(request: { prefix: string; new_length: number; index?: number }): string };
    lease: {
      list(): Array<{ type: string; key: string; metadata: Record<string, VeerJSONValue>; created_at?: string; updated_at?: string }>;
      restore(type: string, key: string): { restored: boolean; type: string; key: string };
    };
    namespace: {
      get(name: string): VeerNetNamespaceInfo | null;
      list(): VeerNetNamespaceInfo[];
      ensure(request: { name: string; loopback_up?: boolean }): VeerNetNamespaceInfo;
      delete(name: string): void;
      release(name: string): void;
      owned(): Array<{ key: string; metadata: Record<string, VeerJSONValue>; created_at?: string; updated_at?: string }>;
    };
    tuntap: {
      ensure(request: VeerNetTunTapRequest): { device: VeerNetTunTapInfo; created: boolean };
      close(request: { name: string; namespace?: string }): void;
      read(request: { name: string; namespace?: string; max_bytes?: number; timeout_ms?: number }): { data: string; bytes: number; timed_out: boolean };
      write(request: { name: string; namespace?: string; data: string }): { bytes: number };
      list(): VeerNetTunTapInfo[];
      owned(): Array<{ key: string; metadata: Record<string, VeerJSONValue>; created_at?: string; updated_at?: string }>;
    };
    l2: VeerNetL2API;
    udp: VeerNetUDPAPI;
    socket: VeerNetSocketAPI;
    http: { request(request: VeerNetHTTPRequest): VeerNetHTTPResponse };
    dns: { lookup(request: VeerNetDNSRequest): VeerNetDNSResponse };
    link: VeerNetLinkAPI;
    addr: VeerNetAddrAPI;
    route: VeerNetMutationAPI<VeerNetRouteRequest>;
    rule: VeerNetMutationAPI<VeerNetRuleRequest>;
    neigh: VeerNetMutationAPI<VeerNetNeighRequest>;
  }

  interface VeerEBPFAPI {
    loadObject(spec: VeerObjectSpec): void;
    mapPut(objectID: string, mapName: string, keyHex: string, valueHex: string): void;
    mapTransaction(request: VeerEBPFMapTransactionRequest): VeerEBPFMapTransactionResult;
    mapGet(objectID: string, mapName: string, keyHex: string): string | null;
    mapGetPerCPU(objectID: string, mapName: string, keyHex: string): string[] | null;
    mapScan(mapName: string, options: VeerEBPFMapScanOptions): VeerEBPFMapScanResult;
    mapScan(objectID: string, mapName: string, options: VeerEBPFMapScanOptions): VeerEBPFMapScanResult;
    mapDelete(objectID: string, mapName: string, keyHex: string): void;
    mapClear(objectID: string, mapName: string): void;
    ringRead(mapName: string, options: VeerEBPFRingReadOptions): VeerEBPFRingReadResult;
    ringRead(objectID: string, mapName: string, options: VeerEBPFRingReadOptions): VeerEBPFRingReadResult;
    ringSubscribe(spec: VeerEBPFRingSubscription): void;
    ringStats(): VeerEBPFRingBusState;
  }

  interface VeerEBPFMapMutation {
    op: 'put' | 'delete';
    object?: string;
    map: string;
    key: string;
    value?: string;
  }

  interface VeerEBPFMapTransactionRequest {
    operations: VeerEBPFMapMutation[];
    commit?: Omit<VeerEBPFMapMutation, 'op'> & { op?: 'put'; value: string };
  }

  interface VeerEBPFMapTransactionResult {
    status: 'completed';
    operations: number;
    committed: boolean;
  }

  interface VeerEBPFMapScanOptions {
    cursor?: string;
    limit?: number;
    max_bytes?: number;
  }

  interface VeerEBPFMapScanResult {
    entries: Array<{ key: string; value: string }>;
    cursor: string;
    done: boolean;
  }

  interface VeerEBPFStateMigrationContext {
    protocol_version: 1;
    object_id: string;
    source_map: string;
    target_map: string;
    from_schema_version: number;
    to_schema_version: number;
    batch: number;
    cursor: string;
    max_entries: number;
    max_bytes: number;
  }

  interface VeerEBPFStateMigrationProgress {
    done: boolean;
    cursor: string;
    processed: number;
  }

  interface VeerEBPFRingReadOptions {
    max_records?: number;
    max_bytes?: number;
    timeout_ms?: number;
  }

  interface VeerEBPFRingReadResult {
    records: Array<{ data: string; size: number; remaining: number }>;
    bytes: number;
    dropped_records: number;
    remaining: number;
    timed_out: boolean;
    limit_reached: boolean;
  }

  interface VeerEBPFRingSubscription {
    id: string;
    object: string;
    map: string;
    worker: string;
    handler: string;
    queue_size?: number;
    max_records?: number;
    max_bytes?: number;
    poll_timeout_ms?: number;
  }

  interface VeerEBPFRingSubscriptionState extends VeerEBPFRingSubscription {
    pending: number;
    pending_bytes: number;
    peak_pending_bytes: number;
    read_calls: number;
    read_records: number;
    read_bytes: number;
    read_dropped_records: number;
    enqueued_batches: number;
    delivered_batches: number;
    dropped_batches: number;
    dropped_records: number;
    read_errors: number;
    handler_errors: number;
    last_read_at?: string;
    last_delivery_at?: string;
    last_error?: string;
  }

  interface VeerEBPFRingBusState {
    subscription_count: number;
    pending: number;
    pending_bytes: number;
    pending_byte_limit: number;
    read_records: number;
    read_bytes: number;
    read_dropped_records: number;
    enqueued_batches: number;
    delivered_batches: number;
    dropped_batches: number;
    dropped_records: number;
    read_errors: number;
    handler_errors: number;
    subscriptions?: VeerEBPFRingSubscriptionState[];
  }

  interface VeerEBPFRingBatch {
    subscription: string;
    object: string;
    map: string;
    records: Array<{ data: string; size: number; remaining: number }>;
    bytes: number;
    dropped_records: number;
    remaining: number;
    limit_reached: boolean;
    read_at: string;
  }

  interface VeerPluginIdentity { id: string; name: string; version: string; }
  interface VeerControlContext {
    kind: string;
    plugin: VeerPluginIdentity;
    host: Partial<VeerPluginHostInfo>;
    payload?: VeerJSONValue;
    resource?: { id: string; runtime_update: VeerRuntimeUpdate };
    records?: VeerResourceRecord[];
    action?: {
      id: string;
      runtime_update: VeerRuntimeUpdate;
      request_schema_version: number;
      response_schema_version: number;
    };
    timer?: VeerTimerState & { fired_at: string };
    worker?: { name: string; handler: string };
    event?: {
      topic: string;
      subscription: string;
      sequence: number;
      published_at: string;
      source_plugin: string;
      target_plugin: string;
      resource: string;
      schema_version: number;
      delivery: 'volatile' | 'durable';
      delivery_id?: string;
      attempt?: number;
      payload: VeerJSONValue;
    };
    socket?: VeerNetSocketEvent;
    ebpf_migration?: VeerEBPFStateMigrationContext;
    upgrade?: Record<string, VeerJSONValue>;
    reason?: string;
    [key: string]: unknown;
  }

  interface VeerPluginExports {
    onReconcile?(ctx: VeerControlContext): VeerJSONValue | void;
    onResourceApply?(ctx: VeerControlContext): VeerJSONValue | void;
    onAction?(ctx: VeerControlContext): VeerJSONValue | void;
    onTimer?(ctx: VeerControlContext): VeerJSONValue | void;
    onEvent?(ctx: VeerControlContext): VeerJSONValue | void;
    onDeactivate?(ctx: VeerControlContext): VeerJSONValue | void;
    onUpgradeSnapshot?(ctx: VeerControlContext): VeerJSONValue | void;
    onUpgradeRestore?(ctx: VeerControlContext): VeerJSONValue | void;
    onResourceMigrate?(ctx: VeerControlContext): { records: Array<{ key: string; data: VeerJSONValue; enabled?: boolean }> };
    onEBPFStateMigrate?(ctx: VeerControlContext): VeerEBPFStateMigrationProgress;
    [handler: string]: ((ctx: VeerControlContext) => VeerJSONValue | VeerEBPFStateMigrationProgress | void) | undefined;
  }

  const plugin: VeerPluginAPI;
  const pipeline: {
    node(spec: VeerVirtualInterfaceSpec): void;
    handoff(spec: VeerVirtualInterfaceSpec): void;
    attach(spec: VeerPipelineAttachSpec): void;
  };
  const hooks: { attach(spec: VeerHookSpec): void };
  const ebpf: VeerEBPFAPI;
  const ui: { register(spec: VeerUIRegistration): void };
  const kv: VeerKVAPI;
  const resources: VeerResourcesAPI;
  const plugins: {
    resources: VeerCrossPluginResourcesAPI;
    actions: { call<T extends VeerJSONValue = VeerJSONValue>(plugin: string, action: string, payload?: VeerJSONValue): T };
    services: VeerServicesAPI;
  };
  const timer: VeerTimerAPI;
  const worker: VeerWorkerAPI;
  const events: VeerEventsAPI;
	const operations: VeerOperationsAPI;
  const metrics: VeerMetricsAPI;
  var crypto: Crypto;
  const secret: VeerSecretAPI;
  const blob: VeerBlobAPI;
  const net: VeerNetAPI;
  const log: { debug(...values: unknown[]): void; info(...values: unknown[]): void; warn(...values: unknown[]): void; error(...values: unknown[]): void };
  const module: { exports: VeerPluginExports };
  const exports: VeerPluginExports;
  function require<T = unknown>(path: string): T;
}
