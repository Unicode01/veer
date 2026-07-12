<?php
/**
 * WHMCS Forward 管理模块
 *
 * 对接 forward 的规则接口，提供端口转发与共享建站管理。
 */

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

use WHMCS\Database\Capsule;

function forward_config()
{
    return [
        'name' => 'Forward 管理',
        'description' => '对接 forward 的规则接口，提供端口转发规则的后台与客户区管理。',
        'version' => '1.3.7',
        'author' => 'OpenAI Codex',
        'language' => 'chinese',
        'fields' => [
            'server_ip' => [
                'FriendlyName' => '默认入口 IP',
                'Type' => 'text',
                'Size' => '50',
                'Description' => '全局默认入口 IP，支持多个 IP（IPv4/IPv6），用逗号/空格/换行分隔；未命中宿主机映射时使用',
                'Default' => '0.0.0.0',
            ],
            'server_ip_server_map' => [
                'FriendlyName' => '按宿主机映射入口 IP',
                'Type' => 'textarea',
                'Rows' => '5',
                'Description' => "按 WHMCS serverID 指定入口 IP，每行一条，格式如 3=203.0.113.10,2001:db8::10；客户区会按所选服务所属宿主机限制可用入口 IP",
                'Default' => '',
            ],
            'api_endpoint' => [
                'FriendlyName' => '默认 Forward API 地址',
                'Type' => 'text',
                'Size' => '50',
                'Description' => '默认 Forward 控制端地址；未命中宿主机覆盖映射时使用，例如 http://127.0.0.1:8080',
                'Default' => 'http://127.0.0.1:8080',
            ],
            'api_token' => [
                'FriendlyName' => '默认 Forward Bearer Token',
                'Type' => 'password',
                'Size' => '50',
                'Description' => '对应 forward 配置里的 web_token；仅作为默认端点令牌，会以 Authorization: Bearer <token> 调用',
                'Default' => '',
            ],
            'api_server_map' => [
                'FriendlyName' => '宿主机覆盖端点映射',
                'Type' => 'textarea',
                'Rows' => '6',
                'Description' => "可选，仅多宿主机/多 Forward 实例需要。每行按 WHMCS serverID 指定 API，格式如 3=https://forward-a.example.com；需要单独 Token 时写 3=https://forward-a.example.com|tokenA，未写 Token 则复用默认 Token",
                'Default' => '',
            ],
            'skip_tls_verify' => [
                'FriendlyName' => '跳过 TLS 验证',
                'Type' => 'yesno',
                'Description' => '仅在你明确使用自签名证书时启用；默认会校验证书',
                'Default' => 'off',
            ],
            'in_interface' => [
                'FriendlyName' => '默认入接口',
                'Type' => 'text',
                'Size' => '25',
                'Description' => '可选，对应规则的 in_interface',
                'Default' => '',
            ],
            'out_interface' => [
                'FriendlyName' => '默认出接口',
                'Type' => 'text',
                'Size' => '25',
                'Description' => '可选，对应规则的 out_interface',
                'Default' => '',
            ],
            'default_tag' => [
                'FriendlyName' => '默认标签',
                'Type' => 'text',
                'Size' => '25',
                'Description' => '可选，对应规则的 tag',
                'Default' => 'whmcs',
            ],
            'transparent_mode' => [
                'FriendlyName' => '默认透传源 IP',
                'Type' => 'yesno',
                'Description' => '新增规则时默认 transparent=true',
                'Default' => 'off',
            ],
            'admin_min_port' => [
                'FriendlyName' => '后台最小入口端口',
                'Type' => 'text',
                'Size' => '10',
                'Description' => '管理员在后台创建/编辑规则时允许使用的最小入口端口',
                'Default' => '1',
            ],
            'admin_max_port' => [
                'FriendlyName' => '后台最大入口端口',
                'Type' => 'text',
                'Size' => '10',
                'Description' => '管理员在后台创建/编辑规则时允许使用的最大入口端口',
                'Default' => '65535',
            ],
            'client_min_port' => [
                'FriendlyName' => '客户区最小入口端口',
                'Type' => 'text',
                'Size' => '10',
                'Description' => '客户区创建/编辑规则时允许使用的最小入口端口',
                'Default' => '10000',
            ],
            'client_max_port' => [
                'FriendlyName' => '客户区最大入口端口',
                'Type' => 'text',
                'Size' => '10',
                'Description' => '客户区创建/编辑规则时允许使用的最大入口端口',
                'Default' => '65535',
            ],
            'enable_client_area' => [
                'FriendlyName' => '启用客户区域',
                'Type' => 'yesno',
                'Description' => '允许客户在前台管理规则',
                'Default' => 'yes',
            ],
            'max_rules_per_user' => [
                'FriendlyName' => '每用户最大规则数',
                'Type' => 'text',
                'Size' => '10',
                'Description' => '客户区每个用户默认最多可创建的端口规则数量；可被下面的按产品规则上限覆盖',
                'Default' => '10',
            ],
            'product_rule_limits' => [
                'FriendlyName' => '按产品规则上限',
                'Type' => 'textarea',
                'Rows' => '4',
                'Description' => "可选。按 WHMCS 产品 ID 覆盖端口规则上限，每行一条，格式如 12=10；0 表示该产品不限。未配置的产品使用“每用户最大规则数”",
                'Default' => '',
            ],
            'max_sites_per_user' => [
                'FriendlyName' => '默认站点上限',
                'Type' => 'text',
                'Size' => '10',
                'Description' => '客户区每个产品默认最多可创建的共享站点数量；可被下面的按产品站点上限覆盖',
                'Default' => '5',
            ],
            'product_site_limits' => [
                'FriendlyName' => '按产品站点上限',
                'Type' => 'textarea',
                'Rows' => '4',
                'Description' => "可选。按 WHMCS 产品 ID 覆盖共享站点上限，每行一条，格式如 12=5；0 表示该产品不限。未配置的产品使用“每用户最大站点数”",
                'Default' => '',
            ],
            'allowed_protocols' => [
                'FriendlyName' => '允许的协议',
                'Type' => 'dropdown',
                'Options' => 'tcp,udp,tcp+udp',
                'Description' => '客户区允许选择的协议',
                'Default' => 'tcp+udp',
            ],
            'client_rule_edit_listen_ip' => [
                'FriendlyName' => '客户区可编辑规则入口 IP',
                'Type' => 'yesno',
                'Description' => '关闭后客户区规则的入口 IP 将按宿主机自动选取，用户不可修改',
                'Default' => 'yes',
            ],
            'client_rule_edit_protocol' => [
                'FriendlyName' => '客户区可编辑规则协议',
                'Type' => 'yesno',
                'Description' => '关闭后客户区规则协议将固定为“允许的协议”配置值',
                'Default' => 'yes',
            ],
            'client_rule_edit_description' => [
                'FriendlyName' => '客户区可编辑规则描述',
                'Type' => 'yesno',
                'Description' => '关闭后客户区不可修改规则描述',
                'Default' => 'yes',
            ],
            'client_site_edit_listen_ip' => [
                'FriendlyName' => '客户区可编辑站点入口 IP',
                'Type' => 'yesno',
                'Description' => '关闭后客户区站点入口 IP 将按宿主机自动选取，用户不可修改',
                'Default' => 'yes',
            ],
            'client_site_edit_backend_ports' => [
                'FriendlyName' => '客户区可编辑站点后端端口',
                'Type' => 'yesno',
                'Description' => '关闭后客户区站点后端端口固定为 80/443 或保留当前值',
                'Default' => 'yes',
            ],
            'client_site_edit_description' => [
                'FriendlyName' => '客户区可编辑站点描述',
                'Type' => 'yesno',
                'Description' => '关闭后客户区不可修改站点描述',
                'Default' => 'yes',
            ],
            'allowed_product_ids' => [
                'FriendlyName' => '允许访问的产品 ID',
                'Type' => 'textarea',
                'Rows' => '3',
                'Description' => '多个产品 ID 用逗号分隔；留空则不限制',
                'Default' => '',
            ],
            'allowed_client_ips' => [
                'FriendlyName' => '客户区可选 IP 白名单',
                'Type' => 'textarea',
                'Rows' => '4',
                'Description' => '多个 IP（IPv4/IPv6）用逗号/空格/换行分隔；留空则不限制（仍受产品 IP 与客户区目标 IP 类型约束）',
                'Default' => '',
            ],
            'client_service_ip_family' => [
                'FriendlyName' => '客户区目标 IP 类型',
                'Type' => 'dropdown',
                'Options' => 'ipv4,all,ipv6',
                'Description' => '默认仅展示 WHMCS 服务中的 IPv4 作为机器 IP；选择 all 才会同时展示 IPv4/IPv6',
                'Default' => 'ipv4',
            ],
        ],
    ];
}

function forward_activate()
{
    try {
        if (!Capsule::schema()->hasTable('mod_forward_rules')) {
            Capsule::schema()->create('mod_forward_rules', function ($table) {
                $table->increments('id');
                $table->unsignedBigInteger('forward_rule_id')->nullable()->unique();
                $table->unsignedBigInteger('remote_rule_id')->nullable();
                $table->integer('user_id')->default(0);
                $table->string('product_name', 100)->nullable();
                $table->integer('server_id')->default(0);
                $table->integer('service_id')->default(0);
                $table->string('rule_name', 100);
                $table->string('in_interface', 100)->default('');
                $table->string('in_ip', 45)->default('0.0.0.0');
                $table->integer('in_port');
                $table->string('out_interface', 100)->default('');
                $table->string('out_ip', 45);
                $table->integer('out_port');
                $table->string('out_source_ip', 45)->default('');
                $table->string('protocol', 20)->default('tcp');
                $table->string('tag', 100)->default('');
                $table->boolean('transparent')->default(false);
                $table->boolean('service_suspended')->default(false);
                $table->string('status', 20)->default('active');
                $table->text('description')->nullable();
                $table->timestamp('created_at')->useCurrent();
                $table->timestamp('updated_at')->useCurrent();
                $table->index(['user_id', 'status'], 'idx_mod_forward_rules_user_status');
                $table->index(['server_id', 'remote_rule_id'], 'idx_mod_forward_rules_server_remote');
                $table->index(['in_ip', 'in_port'], 'idx_mod_forward_rules_listen');
            });
        } else {
            $columns = [
                'forward_rule_id' => function ($table) { $table->unsignedBigInteger('forward_rule_id')->nullable()->unique()->after('id'); },
                'remote_rule_id' => function ($table) { $table->unsignedBigInteger('remote_rule_id')->nullable()->after('forward_rule_id'); },
                'user_id' => function ($table) { $table->integer('user_id')->default(0)->after('remote_rule_id'); },
                'product_name' => function ($table) { $table->string('product_name', 100)->nullable()->after('user_id'); },
                'server_id' => function ($table) { $table->integer('server_id')->default(0)->after('product_name'); },
                'service_id' => function ($table) { $table->integer('service_id')->default(0)->after('server_id'); },
                'rule_name' => function ($table) { $table->string('rule_name', 100)->default('')->after('service_id'); },
                'in_interface' => function ($table) { $table->string('in_interface', 100)->default('')->after('rule_name'); },
                'in_ip' => function ($table) { $table->string('in_ip', 45)->default('0.0.0.0')->after('in_interface'); },
                'in_port' => function ($table) { $table->integer('in_port')->default(0)->after('in_ip'); },
                'out_interface' => function ($table) { $table->string('out_interface', 100)->default('')->after('in_port'); },
                'out_ip' => function ($table) { $table->string('out_ip', 45)->default('')->after('out_interface'); },
                'out_port' => function ($table) { $table->integer('out_port')->default(0)->after('out_ip'); },
                'out_source_ip' => function ($table) { $table->string('out_source_ip', 45)->default('')->after('out_port'); },
                'protocol' => function ($table) { $table->string('protocol', 20)->default('tcp')->after('out_source_ip'); },
                'tag' => function ($table) { $table->string('tag', 100)->default('')->after('protocol'); },
                'transparent' => function ($table) { $table->boolean('transparent')->default(false)->after('tag'); },
                'service_suspended' => function ($table) { $table->boolean('service_suspended')->default(false)->after('transparent'); },
                'status' => function ($table) { $table->string('status', 20)->default('active')->after('service_suspended'); },
                'description' => function ($table) { $table->text('description')->nullable()->after('status'); },
                'created_at' => function ($table) { $table->timestamp('created_at')->useCurrent()->after('description'); },
                'updated_at' => function ($table) { $table->timestamp('updated_at')->useCurrent()->after('created_at'); },
            ];
            foreach ($columns as $column => $callback) {
                if (!Capsule::schema()->hasColumn('mod_forward_rules', $column)) {
                    Capsule::schema()->table('mod_forward_rules', $callback);
                }
            }
        }

        if (!Capsule::schema()->hasTable('mod_forward_sites')) {
            Capsule::schema()->create('mod_forward_sites', function ($table) {
                $table->increments('id');
                $table->unsignedBigInteger('forward_site_id')->nullable()->unique();
                $table->unsignedBigInteger('remote_site_id')->nullable();
                $table->integer('user_id')->default(0);
                $table->string('product_name', 100)->nullable();
                $table->integer('server_id')->default(0);
                $table->integer('service_id')->default(0);
                $table->string('domain', 253);
                $table->string('listen_interface', 100)->default('');
                $table->string('listen_ip', 45)->default('0.0.0.0');
                $table->string('backend_ip', 45);
                $table->string('backend_source_ip', 45)->default('');
                $table->integer('backend_http_port')->default(80);
                $table->integer('backend_https_port')->default(443);
                $table->string('tag', 100)->default('');
                $table->boolean('transparent')->default(false);
                $table->boolean('service_suspended')->default(false);
                $table->string('status', 20)->default('active');
                $table->text('description')->nullable();
                $table->timestamp('created_at')->useCurrent();
                $table->timestamp('updated_at')->useCurrent();
                $table->index(['user_id', 'status'], 'idx_mod_forward_sites_user_status');
                $table->index(['server_id', 'remote_site_id'], 'idx_mod_forward_sites_server_remote');
                $table->index(['domain'], 'idx_mod_forward_sites_domain');
                $table->index(['backend_ip'], 'idx_mod_forward_sites_backend_ip');
            });
        } else {
            $columns = [
                'forward_site_id' => function ($table) { $table->unsignedBigInteger('forward_site_id')->nullable()->unique()->after('id'); },
                'remote_site_id' => function ($table) { $table->unsignedBigInteger('remote_site_id')->nullable()->after('forward_site_id'); },
                'user_id' => function ($table) { $table->integer('user_id')->default(0)->after('remote_site_id'); },
                'product_name' => function ($table) { $table->string('product_name', 100)->nullable()->after('user_id'); },
                'server_id' => function ($table) { $table->integer('server_id')->default(0)->after('product_name'); },
                'service_id' => function ($table) { $table->integer('service_id')->default(0)->after('server_id'); },
                'domain' => function ($table) { $table->string('domain', 253)->default('')->after('service_id'); },
                'listen_interface' => function ($table) { $table->string('listen_interface', 100)->default('')->after('domain'); },
                'listen_ip' => function ($table) { $table->string('listen_ip', 45)->default('0.0.0.0')->after('listen_interface'); },
                'backend_ip' => function ($table) { $table->string('backend_ip', 45)->default('')->after('listen_ip'); },
                'backend_source_ip' => function ($table) { $table->string('backend_source_ip', 45)->default('')->after('backend_ip'); },
                'backend_http_port' => function ($table) { $table->integer('backend_http_port')->default(80)->after('backend_source_ip'); },
                'backend_https_port' => function ($table) { $table->integer('backend_https_port')->default(443)->after('backend_http_port'); },
                'tag' => function ($table) { $table->string('tag', 100)->default('')->after('backend_https_port'); },
                'transparent' => function ($table) { $table->boolean('transparent')->default(false)->after('tag'); },
                'service_suspended' => function ($table) { $table->boolean('service_suspended')->default(false)->after('transparent'); },
                'status' => function ($table) { $table->string('status', 20)->default('active')->after('service_suspended'); },
                'description' => function ($table) { $table->text('description')->nullable()->after('status'); },
                'created_at' => function ($table) { $table->timestamp('created_at')->useCurrent()->after('description'); },
                'updated_at' => function ($table) { $table->timestamp('updated_at')->useCurrent()->after('created_at'); },
            ];
            foreach ($columns as $column => $callback) {
                if (!Capsule::schema()->hasColumn('mod_forward_sites', $column)) {
                    Capsule::schema()->table('mod_forward_sites', $callback);
                }
            }
        }

        return ['status' => 'success', 'description' => 'Forward 模块已成功安装。'];
    } catch (Exception $e) {
        return ['status' => 'error', 'description' => '模块安装失败：' . $e->getMessage()];
    }
}

function forward_deactivate()
{
    return ['status' => 'success', 'description' => 'Forward 模块已停用，数据已保留。'];
}

function forward_get_module_settings()
{
    try {
        return Capsule::table('tbladdonmodules')
            ->where('module', 'forward')
            ->pluck('value', 'setting')
            ->toArray();
    } catch (Exception $e) {
        forward_log('get_module_settings_error', [], $e->getMessage());
        return [];
    }
}

function forward_list_table_indexes($table)
{
    $table = trim((string) $table);
    if ($table === '') {
        return [];
    }

    try {
        $rows = Capsule::select('SHOW INDEX FROM `' . str_replace('`', '``', $table) . '`');
    } catch (Throwable $e) {
        forward_log('list_table_indexes_error', ['table' => $table], $e->getMessage());
        return [];
    }

    $indexes = [];
    foreach ($rows as $row) {
        $name = strtolower(trim((string) ($row->Key_name ?? '')));
        $column = strtolower(trim((string) ($row->Column_name ?? '')));
        $seq = (int) ($row->Seq_in_index ?? 0);
        if ($name === '' || $column === '' || $seq <= 0) {
            continue;
        }

        if (!isset($indexes[$name])) {
            $indexes[$name] = [
                'unique' => (int) ($row->Non_unique ?? 1) === 0,
                'columns' => [],
            ];
        }
        $indexes[$name]['columns'][$seq] = $column;
    }

    foreach ($indexes as $name => $index) {
        ksort($indexes[$name]['columns']);
        $indexes[$name]['columns'] = array_values($indexes[$name]['columns']);
    }

    return $indexes;
}

function forward_table_has_index($table, array $columns, $unique = null)
{
    $expected = [];
    foreach ($columns as $column) {
        $column = strtolower(trim((string) $column));
        if ($column !== '') {
            $expected[] = $column;
        }
    }
    if (empty($expected)) {
        return false;
    }

    $indexes = forward_list_table_indexes($table);
    foreach ($indexes as $index) {
        if ($unique !== null && (bool) ($index['unique'] ?? false) !== (bool) $unique) {
            continue;
        }
        if (($index['columns'] ?? []) === $expected) {
            return true;
        }
    }

    return false;
}

function forward_ensure_table_index($table, array $columns, $name, $unique = false)
{
    $table = trim((string) $table);
    if ($table === '' || !Capsule::schema()->hasTable($table)) {
        return;
    }
    if (forward_table_has_index($table, $columns, $unique)) {
        return;
    }

    try {
        Capsule::schema()->table($table, function ($schema) use ($columns, $name, $unique) {
            if ($unique) {
                $schema->unique($columns, $name);
            } else {
                $schema->index($columns, $name);
            }
        });
    } catch (Throwable $e) {
        if (!forward_table_has_index($table, $columns, $unique)) {
            forward_log('ensure_table_index_error', [
                'table' => $table,
                'index' => $name,
                'columns' => implode(',', $columns),
                'unique' => $unique ? '1' : '0',
            ], $e->getMessage());
        }
    }
}

function forward_ensure_runtime_indexes()
{
    forward_ensure_table_index('mod_forward_rules', ['user_id', 'status'], 'idx_mod_forward_rules_user_status');
    forward_ensure_table_index('mod_forward_rules', ['server_id', 'remote_rule_id'], 'idx_mod_forward_rules_server_remote');
    forward_ensure_table_index('mod_forward_rules', ['in_ip', 'in_port'], 'idx_mod_forward_rules_listen');

    forward_ensure_table_index('mod_forward_sites', ['user_id', 'status'], 'idx_mod_forward_sites_user_status');
    forward_ensure_table_index('mod_forward_sites', ['server_id', 'remote_site_id'], 'idx_mod_forward_sites_server_remote');
    forward_ensure_table_index('mod_forward_sites', ['domain'], 'idx_mod_forward_sites_domain');
    forward_ensure_table_index('mod_forward_sites', ['backend_ip'], 'idx_mod_forward_sites_backend_ip');
}

function forward_get_server_details_map()
{
    static $map = null;
    if ($map !== null) {
        return $map;
    }

    $map = [];
    try {
        $rows = Capsule::table('tblservers')
            ->select('id', 'name', 'hostname')
            ->get();
        foreach ($rows as $row) {
            $map[(int) $row->id] = [
                'name' => trim((string) ($row->name ?? '')),
                'hostname' => trim((string) ($row->hostname ?? '')),
            ];
        }
    } catch (Exception $e) {
        forward_log('get_server_details_map_error', [], $e->getMessage());
    }

    return $map;
}

function forward_format_server_label($serverId, $serverName = '', $serverHostname = '')
{
    $serverId = (int) $serverId;
    $serverName = trim((string) $serverName);
    $serverHostname = trim((string) $serverHostname);

    if ($serverName !== '') {
        return $serverHostname !== '' ? ($serverName . ' (' . $serverHostname . ')') : $serverName;
    }
    if ($serverHostname !== '') {
        return $serverHostname;
    }
    if ($serverId > 0) {
        return '宿主机 #' . $serverId;
    }

    return '未分配宿主机';
}

function forward_get_server_label($serverId)
{
    $serverId = (int) $serverId;
    if ($serverId <= 0) {
        return forward_format_server_label(0);
    }

    $map = forward_get_server_details_map();
    $server = $map[$serverId] ?? ['name' => '', 'hostname' => ''];
    return forward_format_server_label($serverId, $server['name'], $server['hostname']);
}

function forward_data_get($source, $key, $default = null)
{
    if (is_array($source)) {
        return array_key_exists($key, $source) ? $source[$key] : $default;
    }
    if (is_object($source) && isset($source->{$key})) {
        return $source->{$key};
    }
    return $default;
}

function forward_parse_server_api_map($value)
{
    $lines = preg_split('/\r\n|\r|\n/', (string) $value);
    $map = [];
    foreach ($lines as $line) {
        $line = trim((string) $line);
        if ($line === '' || strpos($line, '#') === 0) {
            continue;
        }
        if (!preg_match('/^(\d+)\s*[:=]\s*(.+)$/', $line, $matches)) {
            continue;
        }

        $serverId = (int) $matches[1];
        $parts = preg_split('/\s*\|\s*/', trim((string) $matches[2]), 2);
        $endpoint = rtrim(trim((string) ($parts[0] ?? '')), '/');
        $token = trim((string) ($parts[1] ?? ''));
        if ($serverId > 0 && $endpoint !== '') {
            $map[$serverId] = [
                'endpoint' => $endpoint,
                'token' => $token,
            ];
        }
    }
    return $map;
}

function forward_has_server_api_map(array $settings)
{
    return trim((string) ($settings['api_server_map'] ?? '')) !== '';
}

function forward_api_target_key($endpoint, $token)
{
    $endpoint = rtrim(trim((string) $endpoint), '/');
    $token = trim((string) $token);

    if ($endpoint === '' && $token === '') {
        return 'api:unconfigured';
    }

    return 'api:' . sha1(strtolower($endpoint) . '|' . $token);
}

function forward_get_api_target(array $settings, $serverId = 0)
{
    $serverId = (int) $serverId;
    $skipTlsVerify = forward_is_enabled_value($settings['skip_tls_verify'] ?? 'off');
    $mapped = forward_parse_server_api_map($settings['api_server_map'] ?? '');
    $endpoint = rtrim((string) ($settings['api_endpoint'] ?? ''), '/');
    $token = trim((string) ($settings['api_token'] ?? ''));
    $source = 'default';

    if ($serverId > 0 && !empty($mapped[$serverId])) {
        $endpoint = $mapped[$serverId]['endpoint'];
        if (trim((string) ($mapped[$serverId]['token'] ?? '')) !== '') {
            $token = $mapped[$serverId]['token'];
        }
        $source = 'mapped';
    }

    return [
        'key' => forward_api_target_key($endpoint, $token),
        'server_id' => $serverId,
        'server_label' => $serverId > 0 ? forward_get_server_label($serverId) : '默认 Forward 端点',
        'endpoint' => $endpoint,
        'token' => $token,
        'skip_tls_verify' => $skipTlsVerify,
        'source' => $source,
    ];
}

function forward_api_target_enabled(array $target)
{
    return trim((string) ($target['endpoint'] ?? '')) !== ''
        && trim((string) ($target['token'] ?? '')) !== '';
}

function forward_api_target_label(array $target)
{
    $serverId = (int) ($target['server_id'] ?? 0);
    if ($serverId > 0) {
        return forward_get_server_label($serverId);
    }
    return trim((string) ($target['server_label'] ?? '')) !== ''
        ? (string) $target['server_label']
        : '默认 Forward 端点';
}

function forward_collect_api_targets(array $settings, array $serverIds)
{
    $targets = [];
    foreach ($serverIds as $serverId) {
        $target = forward_get_api_target($settings, (int) $serverId);
        if (!forward_api_target_enabled($target)) {
            continue;
        }
        $targets[$target['key']] = $target;
    }
    if (empty($targets)) {
        $default = forward_get_api_target($settings, 0);
        if (forward_api_target_enabled($default)) {
            $targets[$default['key']] = $default;
        }
    }
    return $targets;
}

function forward_collect_configured_api_targets(array $settings)
{
    $targets = [];
    $mapped = forward_parse_server_api_map($settings['api_server_map'] ?? '');
    foreach (array_keys($mapped) as $serverId) {
        $target = forward_get_api_target($settings, (int) $serverId);
        if (forward_api_target_enabled($target)) {
            $targets[$target['key']] = $target;
        }
    }

    $default = forward_get_api_target($settings, 0);
    if (forward_api_target_enabled($default) && !isset($targets[$default['key']])) {
        $targets[$default['key']] = $default;
    }

    return $targets;
}

function forward_infer_server_id_from_listen_ip(array $settings, $listenIp)
{
    $listenIp = forward_normalize_ip_literal($listenIp);
    if ($listenIp === '' || forward_ip_is_wildcard($listenIp)) {
        return 0;
    }

    $mappedIps = forward_parse_server_ip_server_map($settings['server_ip_server_map'] ?? '');
    $matches = [];
    foreach ($mappedIps as $serverId => $ips) {
        if (in_array($listenIp, $ips, true)) {
            $matches[] = (int) $serverId;
        }
    }

    if (count($matches) === 1) {
        return $matches[0];
    }
    if (count($matches) > 1) {
        return -1;
    }
    return 0;
}

function forward_resolve_target_server_id(array $settings, $listenIp, $serverId = 0)
{
    $serverId = (int) $serverId;
    if ($serverId > 0) {
        $target = forward_get_api_target($settings, $serverId);
        if (!forward_api_target_enabled($target)) {
            return ['success' => false, 'message' => '所选宿主机未配置 Forward 端点'];
        }
        return ['success' => true, 'server_id' => $serverId];
    }

    $inferredServerId = forward_infer_server_id_from_listen_ip($settings, $listenIp);
    if ($inferredServerId < 0) {
        return ['success' => false, 'message' => '该入口 IP 同时映射到多个宿主机，请明确指定宿主机'];
    }
    if ($inferredServerId > 0) {
        $target = forward_get_api_target($settings, $inferredServerId);
        if (!forward_api_target_enabled($target)) {
            return ['success' => false, 'message' => '入口 IP 所属宿主机未配置 Forward 端点'];
        }
        return ['success' => true, 'server_id' => $inferredServerId];
    }

    $target = forward_get_api_target($settings, 0);
    if (!forward_api_target_enabled($target) && forward_has_server_api_map($settings)) {
        return ['success' => false, 'message' => '当前规则无法定位到可用的 Forward 端点，请检查 server_id 与入口 IP 映射'];
    }
    return ['success' => true, 'server_id' => 0];
}

function forward_resolve_record_server_id($record, array $settings, $listenIpField)
{
    $serverId = (int) forward_data_get($record, 'server_id', 0);
    if ($serverId > 0) {
        return $serverId;
    }

    $inferred = forward_infer_server_id_from_listen_ip($settings, forward_data_get($record, $listenIpField, ''));
    return $inferred > 0 ? $inferred : 0;
}

function forward_get_rule_remote_id($record)
{
    return (int) (forward_data_get($record, 'remote_rule_id', 0) ?: forward_data_get($record, 'forward_rule_id', 0));
}

function forward_get_site_remote_id($record)
{
    return (int) (forward_data_get($record, 'remote_site_id', 0) ?: forward_data_get($record, 'forward_site_id', 0));
}

function forward_format_api_target_summary(array $settings)
{
    $mapped = forward_parse_server_api_map($settings['api_server_map'] ?? '');
    $parts = [];
    foreach ($mapped as $serverId => $config) {
        $parts[] = forward_get_server_label($serverId) . ' -> ' . $config['endpoint'];
    }
    $defaultEndpoint = rtrim((string) ($settings['api_endpoint'] ?? ''), '/');
    if ($defaultEndpoint !== '') {
        $parts[] = '默认 -> ' . $defaultEndpoint;
    }
    return !empty($parts) ? implode(' | ', $parts) : '未配置';
}

function forward_has_legacy_server_ip_product_map(array $settings)
{
    return trim((string) ($settings['server_ip_server_map'] ?? '')) === ''
        && trim((string) ($settings['server_ip_product_map'] ?? '')) !== '';
}

function forward_ensure_runtime_schema()
{
    static $checked = false;
    if ($checked) {
        return;
    }
    $checked = true;

    try {
        if (Capsule::schema()->hasTable('mod_forward_rules') && !Capsule::schema()->hasColumn('mod_forward_rules', 'remote_rule_id')) {
            Capsule::schema()->table('mod_forward_rules', function ($table) {
                $table->unsignedBigInteger('remote_rule_id')->nullable()->after('forward_rule_id');
            });
        }
        if (Capsule::schema()->hasTable('mod_forward_rules') && !Capsule::schema()->hasColumn('mod_forward_rules', 'server_id')) {
            Capsule::schema()->table('mod_forward_rules', function ($table) {
                $table->integer('server_id')->default(0)->after('product_name');
            });
        }
        if (Capsule::schema()->hasTable('mod_forward_rules') && !Capsule::schema()->hasColumn('mod_forward_rules', 'service_id')) {
            Capsule::schema()->table('mod_forward_rules', function ($table) {
                $table->integer('service_id')->default(0)->after('server_id');
            });
        }
        if (Capsule::schema()->hasTable('mod_forward_rules') && !Capsule::schema()->hasColumn('mod_forward_rules', 'out_source_ip')) {
            Capsule::schema()->table('mod_forward_rules', function ($table) {
                $table->string('out_source_ip', 45)->default('')->after('out_port');
            });
        }
        if (Capsule::schema()->hasTable('mod_forward_rules') && !Capsule::schema()->hasColumn('mod_forward_rules', 'service_suspended')) {
            Capsule::schema()->table('mod_forward_rules', function ($table) {
                $table->boolean('service_suspended')->default(false)->after('transparent');
            });
        }

        if (Capsule::schema()->hasTable('mod_forward_sites') && !Capsule::schema()->hasColumn('mod_forward_sites', 'remote_site_id')) {
            Capsule::schema()->table('mod_forward_sites', function ($table) {
                $table->unsignedBigInteger('remote_site_id')->nullable()->after('forward_site_id');
            });
        }
        if (Capsule::schema()->hasTable('mod_forward_sites') && !Capsule::schema()->hasColumn('mod_forward_sites', 'server_id')) {
            Capsule::schema()->table('mod_forward_sites', function ($table) {
                $table->integer('server_id')->default(0)->after('product_name');
            });
        }
        if (Capsule::schema()->hasTable('mod_forward_sites') && !Capsule::schema()->hasColumn('mod_forward_sites', 'service_id')) {
            Capsule::schema()->table('mod_forward_sites', function ($table) {
                $table->integer('service_id')->default(0)->after('server_id');
            });
        }
        if (Capsule::schema()->hasTable('mod_forward_sites') && !Capsule::schema()->hasColumn('mod_forward_sites', 'backend_source_ip')) {
            Capsule::schema()->table('mod_forward_sites', function ($table) {
                $table->string('backend_source_ip', 45)->default('')->after('backend_ip');
            });
        }
        if (Capsule::schema()->hasTable('mod_forward_sites') && !Capsule::schema()->hasColumn('mod_forward_sites', 'service_suspended')) {
            Capsule::schema()->table('mod_forward_sites', function ($table) {
                $table->boolean('service_suspended')->default(false)->after('transparent');
            });
        }
    } catch (Exception $e) {
        forward_log('ensure_runtime_schema_error', [], $e->getMessage());
    }

    forward_ensure_runtime_indexes();
    forward_backfill_remote_resource_ids();
    forward_backfill_endpoint_server_bindings();
    forward_backfill_local_service_bindings();
}

function forward_log_key_is_sensitive($key)
{
    $key = strtolower((string) $key);
    foreach (['token', 'password', 'secret', 'authorization', 'csrf', 'bearer'] as $needle) {
        if (strpos($key, $needle) !== false) {
            return true;
        }
    }
    return false;
}

function forward_sanitize_log_value($value, $key = '')
{
    if (forward_log_key_is_sensitive($key)) {
        return '[redacted]';
    }

    if (is_array($value)) {
        $out = [];
        foreach ($value as $itemKey => $itemValue) {
            $out[$itemKey] = forward_sanitize_log_value($itemValue, $itemKey);
        }
        return $out;
    }

    if (is_object($value)) {
        return forward_sanitize_log_value(get_object_vars($value), $key);
    }

    if (is_string($value) && strlen($value) > 4000) {
        return substr($value, 0, 4000) . '... [truncated]';
    }

    return $value;
}

function forward_log_to_string($value)
{
    if ($value === null || $value === '') {
        return '';
    }
    if (is_scalar($value)) {
        return (string) $value;
    }
    $encoded = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    return $encoded === false ? '[unserializable]' : $encoded;
}

function forward_log($action, $request = null, $response = null, $processed = '')
{
    $safeRequest = forward_sanitize_log_value($request);
    $safeResponse = forward_sanitize_log_value($response);
    $safeProcessed = forward_sanitize_log_value($processed);
    $moduleLogError = '';

    if (function_exists('logModuleCall')) {
        try {
            logModuleCall('forward', $action, $safeRequest, $safeResponse, $safeProcessed);
        } catch (Throwable $e) {
            $moduleLogError = $e->getMessage();
        }
    } else {
        $moduleLogError = 'logModuleCall unavailable';
    }

    $activityMessage = 'Forward module: ' . (string) $action;
    $responseText = forward_log_to_string($safeResponse);
    if ($responseText !== '') {
        $activityMessage .= ' | ' . substr($responseText, 0, 1000);
    }
    if ($moduleLogError !== '') {
        $activityMessage .= ' | module log fallback: ' . $moduleLogError;
    }

    if (function_exists('logActivity')) {
        try {
            logActivity($activityMessage);
            return;
        } catch (Throwable $e) {
            $activityMessage .= ' | activity log failed: ' . $e->getMessage();
        }
    }

    if (function_exists('error_log')) {
        @error_log($activityMessage);
    }
}

function forward_get_csrf_token()
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        @session_start();
    }

    if (empty($_SESSION['forward_csrf_token'])) {
        if (function_exists('random_bytes')) {
            $_SESSION['forward_csrf_token'] = bin2hex(random_bytes(16));
        } else {
            $_SESSION['forward_csrf_token'] = md5(uniqid('forward', true));
        }
    }

    return (string) $_SESSION['forward_csrf_token'];
}

function forward_validate_csrf_token($token)
{
    $expected = forward_get_csrf_token();
    return is_string($token) && $token !== '' && hash_equals($expected, $token);
}

function forward_is_enabled_value($value)
{
    return in_array(strtolower((string) $value), ['1', 'true', 'yes', 'on'], true);
}

function forward_resolve_checkbox_value(array $data, $key, $default = false)
{
    if (array_key_exists($key, $data)) {
        return forward_is_enabled_value($data[$key]);
    }
    return (bool) $default;
}

function forward_strlen($value)
{
    if (function_exists('mb_strlen')) {
        return mb_strlen((string) $value, 'UTF-8');
    }
    return strlen((string) $value);
}

function forward_normalize_protocol($protocol)
{
    $value = strtolower(trim((string) $protocol));
    if ($value === 'tcp/udp') {
        $value = 'tcp+udp';
    }
    return in_array($value, ['tcp', 'udp', 'tcp+udp'], true) ? $value : '';
}

function forward_protocol_options($setting)
{
    $normalized = forward_normalize_protocol($setting);
    if ($normalized === 'tcp') {
        return ['tcp'];
    }
    if ($normalized === 'udp') {
        return ['udp'];
    }
    return ['tcp', 'udp', 'tcp+udp'];
}

function forward_protocol_conflicts($protocol)
{
    $normalized = forward_normalize_protocol($protocol);
    if ($normalized === 'tcp') {
        return ['tcp', 'tcp+udp'];
    }
    if ($normalized === 'udp') {
        return ['udp', 'tcp+udp'];
    }
    return ['tcp', 'udp', 'tcp+udp'];
}

function forward_is_valid_ipv4($ip)
{
    return forward_ip_family($ip) === 'ipv4';
}

function forward_normalize_ip_literal($ip)
{
    $value = trim((string) $ip);
    if ($value === '') {
        return '';
    }

    $packed = @inet_pton($value);
    if ($packed === false) {
        return '';
    }

    $normalized = @inet_ntop($packed);
    return is_string($normalized) ? $normalized : '';
}

function forward_is_valid_ip($ip)
{
    return forward_normalize_ip_literal($ip) !== '';
}

function forward_ip_family($ip)
{
    $normalized = forward_normalize_ip_literal($ip);
    if ($normalized === '') {
        return '';
    }

    return filter_var($normalized, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? 'ipv4' : 'ipv6';
}

function forward_normalize_ip_list($value)
{
    $raw = preg_split('/[\s,]+/', (string) $value, -1, PREG_SPLIT_NO_EMPTY);
    $ips = [];
    foreach ($raw as $item) {
        $normalized = forward_normalize_ip_literal($item);
        if ($normalized !== '') {
            $ips[$normalized] = $normalized;
        }
    }
    return array_values($ips);
}

function forward_normalize_optional_ip($ip)
{
    $value = trim((string) $ip);
    if ($value === '') {
        return ['success' => true, 'value' => ''];
    }

    $normalized = forward_normalize_ip_literal($value);
    if ($normalized === '') {
        return ['success' => false, 'message' => '必须是有效的 IP 地址'];
    }

    return ['success' => true, 'value' => $normalized];
}

function forward_normalize_optional_ipv4($ip)
{
    $value = trim((string) $ip);
    if ($value === '') {
        return ['success' => true, 'value' => ''];
    }

    $normalized = forward_normalize_ip_literal($value);
    if ($normalized === '' || forward_ip_family($normalized) !== 'ipv4') {
        return ['success' => false, 'message' => '必须是有效的 IPv4 地址'];
    }

    return ['success' => true, 'value' => $normalized];
}

function forward_ip_is_wildcard($ip)
{
    $normalized = forward_normalize_ip_literal($ip);
    return $normalized === '0.0.0.0' || $normalized === '::';
}

function forward_ip_pair_is_pure_ipv4($leftIp, $rightIp)
{
    return forward_ip_family($leftIp) === 'ipv4' && forward_ip_family($rightIp) === 'ipv4';
}

function forward_find_matching_ip($value, array $allowedIps)
{
    $normalized = forward_normalize_ip_literal($value);
    if ($normalized === '') {
        return '';
    }

    foreach ($allowedIps as $ip) {
        $candidate = forward_normalize_ip_literal($ip);
        if ($candidate !== '' && $candidate === $normalized) {
            return $candidate;
        }
    }

    return '';
}

function forward_ips_conflict($leftIp, $rightIp)
{
    $left = forward_normalize_ip_literal($leftIp);
    $right = forward_normalize_ip_literal($rightIp);
    if ($left === '' || $right === '') {
        return false;
    }

    if ($left === $right) {
        return true;
    }

    $leftFamily = forward_ip_family($left);
    $rightFamily = forward_ip_family($right);
    if ($leftFamily === '' || $leftFamily !== $rightFamily) {
        return false;
    }

    return forward_ip_is_wildcard($left) || forward_ip_is_wildcard($right);
}

function forward_parse_allowed_product_ids($value)
{
    $raw = preg_split('/[\s,]+/', (string) $value, -1, PREG_SPLIT_NO_EMPTY);
    $ids = [];
    foreach ($raw as $item) {
        $id = (int) trim($item);
        if ($id > 0) {
            $ids[] = $id;
        }
    }
    return array_values(array_unique($ids));
}

function forward_parse_product_rule_limits($value)
{
    $lines = preg_split('/\r\n|\r|\n/', (string) $value);
    $limits = [];
    foreach ($lines as $line) {
        $line = trim((string) $line);
        if ($line === '' || strpos($line, '#') === 0) {
            continue;
        }
        if (!preg_match('/^(\d+)\s*[:=]\s*(\d+)$/', $line, $matches)) {
            continue;
        }
        $productId = (int) $matches[1];
        $limit = (int) $matches[2];
        if ($productId > 0) {
            $limits[$productId] = max(0, $limit);
        }
    }
    return $limits;
}

function forward_parse_product_site_limits($value)
{
    $lines = preg_split('/\r\n|\r|\n/', (string) $value);
    $limits = [];
    foreach ($lines as $line) {
        $line = trim((string) $line);
        if ($line === '' || strpos($line, '#') === 0) {
            continue;
        }
        if (!preg_match('/^(\d+)\s*[:=]\s*(\d+)$/', $line, $matches)) {
            continue;
        }
        $productId = (int) $matches[1];
        $limit = (int) $matches[2];
        if ($productId > 0) {
            $limits[$productId] = max(0, $limit);
        }
    }
    return $limits;
}

function forward_default_rule_limit(array $settings)
{
    return max(0, (int) ($settings['max_rules_per_user'] ?? 10));
}

function forward_rule_limit_for_product(array $settings, $productId)
{
    $productId = (int) $productId;
    $limits = forward_parse_product_rule_limits($settings['product_rule_limits'] ?? '');
    if ($productId > 0 && array_key_exists($productId, $limits)) {
        return (int) $limits[$productId];
    }
    return forward_default_rule_limit($settings);
}

function forward_default_site_limit(array $settings)
{
    return max(0, (int) ($settings['max_sites_per_user'] ?? 5));
}

function forward_site_limit_for_product(array $settings, $productId)
{
    $productId = (int) $productId;
    $limits = forward_parse_product_site_limits($settings['product_site_limits'] ?? '');
    if ($productId > 0 && array_key_exists($productId, $limits)) {
        return (int) $limits[$productId];
    }
    return forward_default_site_limit($settings);
}

function forward_parse_allowed_client_ips($value)
{
    return forward_normalize_ip_list($value);
}

function forward_parse_server_ips($value)
{
    return forward_normalize_ip_list($value);
}

function forward_parse_server_ip_server_map($value)
{
    $lines = preg_split('/\r\n|\r|\n/', (string) $value);
    $map = [];
    foreach ($lines as $line) {
        $line = trim((string) $line);
        if ($line === '' || strpos($line, '#') === 0) {
            continue;
        }
        if (!preg_match('/^(\d+)\s*[:=]\s*(.+)$/', $line, $matches)) {
            continue;
        }

        $serverId = (int) $matches[1];
        $ips = forward_parse_server_ips($matches[2]);
        if ($serverId > 0 && !empty($ips)) {
            $map[$serverId] = $ips;
        }
    }
    return $map;
}

function forward_get_allowed_server_ips(array $settings, $serverId = 0)
{
    $serverId = (int) $serverId;
    $defaultIps = forward_parse_server_ips($settings['server_ip'] ?? '');
    $mappedIps = forward_parse_server_ip_server_map($settings['server_ip_server_map'] ?? '');

    if ($serverId > 0 && !empty($mappedIps[$serverId])) {
        return $mappedIps[$serverId];
    }

    return !empty($defaultIps) ? $defaultIps : [];
}

function forward_get_all_server_ips(array $settings)
{
    $all = forward_parse_server_ips($settings['server_ip'] ?? '');
    $mappedIps = forward_parse_server_ip_server_map($settings['server_ip_server_map'] ?? '');
    foreach ($mappedIps as $ips) {
        $all = array_merge($all, $ips);
    }
    $all = array_values(array_unique($all));
    return !empty($all) ? $all : ['0.0.0.0'];
}

function forward_parse_port_setting($value, $default)
{
    $value = trim((string) $value);
    if ($value === '' || !preg_match('/^-?\d+$/', $value)) {
        return [
            'value' => max(1, min(65535, (int) $default)),
            'explicit' => false,
        ];
    }

    return [
        'value' => max(1, min(65535, (int) $value)),
        'explicit' => true,
    ];
}

function forward_get_listen_port_range(array $settings, $isClient = false)
{
    $defaultMin = $isClient ? 10000 : 1;
    $defaultMax = 65535;
    $minSetting = forward_parse_port_setting($settings[$isClient ? 'client_min_port' : 'admin_min_port'] ?? '', $defaultMin);
    $maxSetting = forward_parse_port_setting($settings[$isClient ? 'client_max_port' : 'admin_max_port'] ?? '', $defaultMax);
    $min = (int) $minSetting['value'];
    $max = (int) $maxSetting['value'];

    if ($max < $min) {
        if (!empty($minSetting['explicit']) && !empty($maxSetting['explicit'])) {
            $tmp = $min;
            $min = $max;
            $max = $tmp;
        } elseif (!empty($minSetting['explicit'])) {
            $max = $min;
        } elseif (!empty($maxSetting['explicit'])) {
            $min = 1;
        } else {
            $min = $defaultMin;
            $max = $defaultMax;
        }
    }

    return [
        'min' => $min,
        'max' => $max,
        'text' => $min . '-' . $max,
    ];
}

function forward_get_admin_server_options(array $settings)
{
    $serverMap = forward_get_server_details_map();
    $serverIpMap = forward_parse_server_ip_server_map($settings['server_ip_server_map'] ?? '');
    $apiMap = forward_parse_server_api_map($settings['api_server_map'] ?? '');
    $defaultListenIps = forward_get_allowed_server_ips($settings, 0);
    $defaultTarget = forward_get_api_target($settings, 0);
    $defaultEnabled = !empty($defaultListenIps) && forward_api_target_enabled($defaultTarget);

    $serverIds = [];
    foreach (array_keys($serverIpMap) as $serverId) {
        $serverIds[(int) $serverId] = true;
    }
    foreach (array_keys($apiMap) as $serverId) {
        $serverIds[(int) $serverId] = true;
    }
    if ($defaultEnabled) {
        foreach (array_keys($serverMap) as $serverId) {
            $serverIds[(int) $serverId] = true;
        }
    }

    ksort($serverIds);

    $options = [];
    if ($defaultEnabled) {
        $options['0'] = [
            'server_id' => 0,
            'server_label' => '默认入口/默认端点',
            'listen_ips' => $defaultListenIps,
            'listen_ips_csv' => implode(',', $defaultListenIps),
            'target_label' => trim((string) ($defaultTarget['endpoint'] ?? '')) !== ''
                ? (string) $defaultTarget['endpoint']
                : '未配置',
        ];
    }

    foreach (array_keys($serverIds) as $serverId) {
        $serverId = (int) $serverId;
        if ($serverId <= 0) {
            continue;
        }

        $listenIps = forward_get_allowed_server_ips($settings, $serverId);
        $target = forward_get_api_target($settings, $serverId);
        if (empty($listenIps) || !forward_api_target_enabled($target)) {
            continue;
        }

        $options[(string) $serverId] = [
            'server_id' => $serverId,
            'server_label' => forward_get_server_label($serverId),
            'listen_ips' => $listenIps,
            'listen_ips_csv' => implode(',', $listenIps),
            'target_label' => trim((string) ($target['endpoint'] ?? '')) !== ''
                ? (string) $target['endpoint']
                : '未配置',
        ];
    }

    return $options;
}

function forward_admin_server_select_html(array $serverOptions)
{
    $html = '<option value="">-- 请选择宿主机 --</option>';
    foreach ($serverOptions as $option) {
        $serverId = (int) ($option['server_id'] ?? 0);
        $label = trim((string) ($option['server_label'] ?? ''));
        if ($label === '') {
            $label = $serverId > 0 ? ('宿主机 #' . $serverId) : '默认入口/默认端点';
        }
        $html .= '<option value="' . $serverId . '">' . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . '</option>';
    }

    return $html;
}

function forward_admin_server_filter_html(array $serverOptions)
{
    $html = '<option value="">全部宿主机</option>';
    foreach ($serverOptions as $option) {
        $serverId = (int) ($option['server_id'] ?? 0);
        $label = trim((string) ($option['server_label'] ?? ''));
        if ($label === '') {
            $label = $serverId > 0 ? ('宿主机 #' . $serverId) : '默认入口/默认端点';
        }
        $html .= '<option value="' . $serverId . '">' . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . '</option>';
    }

    return $html;
}

function forward_pick_listen_ip($value, array $allowedIps)
{
    $listenIp = trim((string) $value);
    if ($listenIp === '') {
        return $allowedIps[0] ?? '';
    }
    return forward_find_matching_ip($listenIp, $allowedIps);
}

function forward_client_permissions(array $settings)
{
    return [
        'rule' => [
            'listen_ip' => forward_is_enabled_value($settings['client_rule_edit_listen_ip'] ?? 'yes'),
            'protocol' => forward_is_enabled_value($settings['client_rule_edit_protocol'] ?? 'yes'),
            'description' => forward_is_enabled_value($settings['client_rule_edit_description'] ?? 'yes'),
        ],
        'site' => [
            'listen_ip' => forward_is_enabled_value($settings['client_site_edit_listen_ip'] ?? 'yes'),
            'backend_ports' => forward_is_enabled_value($settings['client_site_edit_backend_ports'] ?? 'yes'),
            'description' => forward_is_enabled_value($settings['client_site_edit_description'] ?? 'yes'),
        ],
    ];
}

function forward_client_default_rule_protocol(array $settings)
{
    $protocol = forward_normalize_protocol($settings['allowed_protocols'] ?? 'tcp+udp');
    if ($protocol !== '') {
        return $protocol;
    }

    $options = forward_protocol_options($settings['allowed_protocols'] ?? 'tcp+udp');
    return $options[0] ?? 'tcp';
}

function forward_client_locked_listen_ip($currentValue, array $allowedIps)
{
    $current = trim((string) $currentValue);
    if ($current !== '') {
        $matched = forward_find_matching_ip($current, $allowedIps);
        if ($matched !== '') {
            return $matched;
        }
    }
    return '';
}

function forward_format_ip_list(array $ips)
{
    $normalized = [];
    foreach ($ips as $ip) {
        $value = forward_normalize_ip_literal($ip);
        if ($value !== '') {
            $normalized[$value] = $value;
        }
    }
    return implode(', ', array_values($normalized));
}

function forward_format_ip_for_endpoint($ip)
{
    $value = trim((string) $ip);
    $normalized = forward_normalize_ip_literal($value);
    if ($normalized !== '') {
        $value = $normalized;
    }

    return forward_ip_family($value) === 'ipv6' ? ('[' . $value . ']') : $value;
}

function forward_format_endpoint_suffix($ip, $suffix = '')
{
    $endpoint = forward_format_ip_for_endpoint($ip);
    $suffix = trim((string) $suffix);
    return $suffix === '' ? $endpoint : ($endpoint . ':' . $suffix);
}

function forward_format_endpoint($ip, $port)
{
    return forward_format_endpoint_suffix($ip, (string) $port);
}

function forward_client_service_ip_family(array $settings = null)
{
    if ($settings === null) {
        $settings = forward_get_module_settings();
    }
    if (!is_array($settings)) {
        $settings = [];
    }

    $family = strtolower(trim((string) ($settings['client_service_ip_family'] ?? 'ipv4')));
    return in_array($family, ['ipv4', 'ipv6', 'all'], true) ? $family : 'ipv4';
}

function forward_filter_service_ips_by_family(array $ips, $family)
{
    $family = strtolower(trim((string) $family));
    if ($family === 'all') {
        return array_values($ips);
    }

    $targetFamily = $family === 'ipv6' ? 'ipv6' : 'ipv4';
    $filtered = [];
    foreach ($ips as $ip) {
        if (forward_ip_family($ip) === $targetFamily) {
            $filtered[] = $ip;
        }
    }
    return array_values($filtered);
}

function forward_attach_service_listen_ips(array $services, array $settings)
{
    $result = [];
    foreach ($services as $service) {
        $serverId = (int) ($service['server_id'] ?? 0);
        $listenIps = forward_get_allowed_server_ips($settings, $serverId);
        $target = forward_get_api_target($settings, $serverId);
        if (empty($listenIps)) {
            continue;
        }
        if (!forward_api_target_enabled($target)) {
            continue;
        }
        $service['listen_ips'] = $listenIps;
        $service['listen_ips_csv'] = implode(',', $listenIps);
        $result[] = $service;
    }
    return $result;
}

function forward_service_from_hosting_row($row, array $allowedClientIps = [], $ipFamily = 'ipv4')
{
    $ips = [];
    if (!empty($row->dedicatedip)) {
        $ips[] = trim((string) $row->dedicatedip);
    }
    if (!empty($row->assignedips)) {
        $parts = preg_split('/[\r\n,\s]+/', (string) $row->assignedips, -1, PREG_SPLIT_NO_EMPTY);
        foreach ($parts as $part) {
            $ips[] = trim((string) $part);
        }
    }

    $ips = forward_normalize_ip_list(implode(' ', $ips));
    $ips = forward_filter_service_ips_by_family($ips, $ipFamily);
    if (!empty($allowedClientIps)) {
        $ips = array_values(array_intersect($ips, $allowedClientIps));
    }
    if (empty($ips)) {
        return null;
    }

    return [
        'user_id' => (int) ($row->user_id ?? $row->userid ?? 0),
        'service_id' => (int) $row->service_id,
        'server_id' => (int) $row->server_id,
        'server_label' => forward_format_server_label($row->server_id, $row->server_name ?? '', $row->server_hostname ?? ''),
        'product_id' => (int) $row->product_id,
        'product_group_id' => (int) $row->product_group_id,
        'product_name' => (string) $row->product_name,
        'domainstatus' => (string) ($row->domainstatus ?? ''),
        'ips' => $ips,
    ];
}

function forward_base_services_query()
{
    return Capsule::table('tblhosting')
        ->join('tblproducts', 'tblhosting.packageid', '=', 'tblproducts.id')
        ->leftJoin('tblservers', 'tblhosting.server', '=', 'tblservers.id')
        ->select(
            'tblhosting.id as service_id',
            'tblhosting.userid as user_id',
            'tblhosting.server as server_id',
            'tblhosting.packageid as product_id',
            'tblhosting.domainstatus',
            'tblhosting.dedicatedip',
            'tblhosting.assignedips',
            'tblproducts.name as product_name',
            'tblproducts.gid as product_group_id',
            'tblservers.name as server_name',
            'tblservers.hostname as server_hostname'
        );
}

function forward_get_user_services($userId, array $allowedProductIds = [], array $allowedClientIps = [], array $statuses = ['Active'], $ipFamily = null)
{
    try {
        $ipFamily = $ipFamily === null ? forward_client_service_ip_family() : $ipFamily;
        $query = forward_base_services_query()
            ->where('tblhosting.userid', (int) $userId);

        if (!empty($statuses)) {
            $query->whereIn('tblhosting.domainstatus', $statuses);
        }

        if (!empty($allowedProductIds)) {
            $query->whereIn('tblhosting.packageid', $allowedProductIds);
        }

        $rows = $query->get();
        $services = [];
        foreach ($rows as $row) {
            $service = forward_service_from_hosting_row($row, $allowedClientIps, $ipFamily);
            if ($service !== null) {
                $services[] = $service;
            }
        }
        return $services;
    } catch (Exception $e) {
        forward_log('get_user_services_error', ['user_id' => $userId], $e->getMessage());
        return [];
    }
}

function forward_get_all_forward_services(array $settings)
{
    try {
        $allowedProductIds = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
        $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
        $query = forward_base_services_query()
            ->whereIn('tblhosting.domainstatus', ['Active', 'Suspended']);

        if (!empty($allowedProductIds)) {
            $query->whereIn('tblhosting.packageid', $allowedProductIds);
        }

        $rows = $query->get();
        $services = [];
        foreach ($rows as $row) {
            $service = forward_service_from_hosting_row($row, $allowedClientIps, 'all');
            if ($service !== null) {
                $services[] = $service;
            }
        }
        return $services;
    } catch (Exception $e) {
        forward_log('get_all_forward_services_error', [], $e->getMessage());
        return [];
    }
}

function forward_get_service_by_id($serviceId, $settings = null, array $statuses = [], $ipFamily = null)
{
    $serviceId = (int) $serviceId;
    if ($serviceId <= 0) {
        return null;
    }

    try {
        $settings = $settings === null ? forward_get_module_settings() : $settings;
        if (!is_array($settings)) {
            $settings = [];
        }
        $allowedProductIds = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
        $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
        $ipFamily = $ipFamily === null ? forward_client_service_ip_family($settings) : $ipFamily;
        $query = forward_base_services_query()->where('tblhosting.id', $serviceId);
        if (!empty($statuses)) {
            $query->whereIn('tblhosting.domainstatus', $statuses);
        }
        if (!empty($allowedProductIds)) {
            $query->whereIn('tblhosting.packageid', $allowedProductIds);
        }

        $row = $query->first();
        return $row ? forward_service_from_hosting_row($row, $allowedClientIps, $ipFamily) : null;
    } catch (Exception $e) {
        forward_log('get_service_by_id_error', ['service_id' => $serviceId], $e->getMessage());
        return null;
    }
}

function forward_group_services_by_product(array $services)
{
    $grouped = [];
    foreach ($services as $service) {
        $name = $service['product_name'] ?: '默认产品';
        if (!isset($grouped[$name])) {
            $grouped[$name] = [];
        }
        $grouped[$name][] = $service;
    }
    return $grouped;
}

function forward_count_service_ips(array $services)
{
    $count = 0;
    foreach ($services as $service) {
        $count += count($service['ips'] ?? []);
    }
    return $count;
}

function forward_find_service_for_ip(array $services, $ip, $serviceId = 0, $serverId = 0, $productName = '')
{
    $ip = forward_normalize_ip_literal($ip);
    $serviceId = (int) $serviceId;
    $serverId = (int) $serverId;
    $productName = trim((string) $productName);
    $matches = [];
    $productMatches = [];

    foreach ($services as $service) {
        if (!in_array($ip, $service['ips'], true)) {
            continue;
        }

        $matches[] = $service;

        if ($serviceId > 0 && (int) ($service['service_id'] ?? 0) === $serviceId) {
            return $service;
        }

        if ($serverId > 0 && (int) ($service['server_id'] ?? 0) === $serverId) {
            return $service;
        }

        $serviceProductName = trim((string) ($service['product_name'] ?? ''));
        if ($productName !== '' && $serviceProductName === $productName) {
            $productMatches[] = $service;
        }
    }

    if ($serviceId > 0) {
        return null;
    }

    if ($serverId > 0) {
        return null;
    }

    if (count($productMatches) === 1) {
        return $productMatches[0];
    }

    if ($productName !== '' && count($productMatches) > 1) {
        return null;
    }

    return count($matches) === 1 ? $matches[0] : null;
}

function forward_count_user_product_rules($userId, $productId, $productName = '')
{
    $userId = (int) $userId;
    $productId = (int) $productId;
    $productName = trim((string) $productName);
    if ($userId <= 0 || ($productId <= 0 && $productName === '')) {
        return 0;
    }

    $services = forward_get_user_services($userId, [], [], [], 'all');
    $serviceProductMap = [];
    foreach ($services as $service) {
        $serviceId = (int) ($service['service_id'] ?? 0);
        if ($serviceId > 0) {
            $serviceProductMap[$serviceId] = (int) ($service['product_id'] ?? 0);
        }
    }

    try {
        $rows = Capsule::table('mod_forward_rules')
            ->where('user_id', $userId)
            ->select('service_id', 'product_name')
            ->get();
        $count = 0;
        foreach ($rows as $row) {
            $serviceId = (int) ($row->service_id ?? 0);
            if ($serviceId > 0 && $productId > 0 && (($serviceProductMap[$serviceId] ?? 0) === $productId)) {
                $count++;
                continue;
            }
            if ($serviceId <= 0 && $productName !== '' && trim((string) ($row->product_name ?? '')) === $productName) {
                $count++;
            }
        }
        return $count;
    } catch (Exception $e) {
        forward_log('count_user_product_rules_error', [
            'user_id' => $userId,
            'product_id' => $productId,
        ], $e->getMessage());
        return 0;
    }
}

function forward_count_user_product_sites($userId, $productId, $productName = '')
{
    $userId = (int) $userId;
    $productId = (int) $productId;
    $productName = trim((string) $productName);
    if ($userId <= 0 || ($productId <= 0 && $productName === '')) {
        return 0;
    }

    $services = forward_get_user_services($userId, [], [], [], 'all');
    $serviceProductMap = [];
    foreach ($services as $service) {
        $serviceId = (int) ($service['service_id'] ?? 0);
        if ($serviceId > 0) {
            $serviceProductMap[$serviceId] = (int) ($service['product_id'] ?? 0);
        }
    }

    try {
        $rows = Capsule::table('mod_forward_sites')
            ->where('user_id', $userId)
            ->select('service_id', 'product_name')
            ->get();
        $count = 0;
        foreach ($rows as $row) {
            $serviceId = (int) ($row->service_id ?? 0);
            if ($serviceId > 0 && $productId > 0 && (($serviceProductMap[$serviceId] ?? 0) === $productId)) {
                $count++;
                continue;
            }
            if ($serviceId <= 0 && $productName !== '' && trim((string) ($row->product_name ?? '')) === $productName) {
                $count++;
            }
        }
        return $count;
    } catch (Exception $e) {
        forward_log('count_user_product_sites_error', [
            'user_id' => $userId,
            'product_id' => $productId,
        ], $e->getMessage());
        return 0;
    }
}

function forward_product_rule_quota(array $settings, $userId, array $service)
{
    $productId = (int) ($service['product_id'] ?? 0);
    $productName = (string) ($service['product_name'] ?? '');
    $limit = forward_rule_limit_for_product($settings, $productId);
    $count = forward_count_user_product_rules($userId, $productId, $productName);
    $remaining = $limit > 0 ? max(0, $limit - $count) : 0;

    return [
        'product_id' => $productId,
        'limit' => $limit,
        'count' => $count,
        'remaining' => $remaining,
        'can_create' => $limit === 0 || $count < $limit,
    ];
}

function forward_product_site_quota(array $settings, $userId, array $service)
{
    $productId = (int) ($service['product_id'] ?? 0);
    $productName = (string) ($service['product_name'] ?? '');
    $limit = forward_site_limit_for_product($settings, $productId);
    $count = forward_count_user_product_sites($userId, $productId, $productName);
    $remaining = $limit > 0 ? max(0, $limit - $count) : 0;

    return [
        'product_id' => $productId,
        'limit' => $limit,
        'count' => $count,
        'remaining' => $remaining,
        'can_create' => $limit === 0 || $count < $limit,
    ];
}

function forward_services_for_quota_group(array $services, array $selectedService)
{
    $productId = (int) ($selectedService['product_id'] ?? 0);
    $productName = trim((string) ($selectedService['product_name'] ?? ''));
    $matches = [];

    foreach ($services as $service) {
        if ($productId > 0) {
            if ((int) ($service['product_id'] ?? 0) === $productId) {
                $matches[] = $service;
            }
            continue;
        }

        if ($productName !== '' && trim((string) ($service['product_name'] ?? '')) === $productName) {
            $matches[] = $service;
        }
    }

    return !empty($matches) ? $matches : [$selectedService];
}

function forward_sync_quota_group_before_create(array $services, array $settings, array $service, $resourceKind, $resourceLabel)
{
    $syncServices = forward_services_for_quota_group($services, $service);
    $result = forward_sync_remote_bindings_for_services($syncServices, $settings, [], false, [$resourceKind]);
    if (!empty($result['errors'])) {
        return [
            'success' => false,
            'message' => '创建前同步当前产品远端配置失败，已取消创建以避免超过' . $resourceLabel . '上限。请稍后重试或联系管理员查看 Forward API 状态。',
            'summary' => $result,
        ];
    }

    return ['success' => true, 'summary' => $result];
}

function forward_attach_service_rule_quotas(array $services, array $settings, $userId)
{
    $quotaCache = [];
    foreach ($services as $index => $service) {
        $productId = (int) ($service['product_id'] ?? 0);
        $productName = (string) ($service['product_name'] ?? '');
        $key = $productId > 0 ? ('id:' . $productId) : ('name:' . $productName);
        if (!isset($quotaCache[$key])) {
            $quotaCache[$key] = forward_product_rule_quota($settings, $userId, $service);
        }
        $services[$index]['rule_quota'] = $quotaCache[$key];
        $services[$index]['rule_limit'] = $quotaCache[$key]['limit'];
        $services[$index]['rule_count'] = $quotaCache[$key]['count'];
        $services[$index]['rule_remaining'] = $quotaCache[$key]['remaining'];
        $services[$index]['rule_can_create'] = $quotaCache[$key]['can_create'];
    }
    return $services;
}

function forward_attach_service_site_quotas(array $services, array $settings, $userId)
{
    $quotaCache = [];
    foreach ($services as $index => $service) {
        $productId = (int) ($service['product_id'] ?? 0);
        $productName = (string) ($service['product_name'] ?? '');
        $key = $productId > 0 ? ('id:' . $productId) : ('name:' . $productName);
        if (!isset($quotaCache[$key])) {
            $quotaCache[$key] = forward_product_site_quota($settings, $userId, $service);
        }
        $services[$index]['site_quota'] = $quotaCache[$key];
        $services[$index]['site_limit'] = $quotaCache[$key]['limit'];
        $services[$index]['site_count'] = $quotaCache[$key]['count'];
        $services[$index]['site_remaining'] = $quotaCache[$key]['remaining'];
        $services[$index]['site_can_create'] = $quotaCache[$key]['can_create'];
    }
    return $services;
}

function forward_any_service_rule_capacity(array $services)
{
    foreach ($services as $service) {
        if (!empty($service['rule_can_create'])) {
            return true;
        }
    }
    return false;
}

function forward_any_service_site_capacity(array $services)
{
    foreach ($services as $service) {
        if (!empty($service['site_can_create'])) {
            return true;
        }
    }
    return false;
}

function forward_backfill_local_service_bindings()
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;

    try {
        $targets = [
            ['table' => 'mod_forward_rules', 'ip_column' => 'out_ip'],
            ['table' => 'mod_forward_sites', 'ip_column' => 'backend_ip'],
        ];
        $serviceCache = [];

        foreach ($targets as $target) {
            if (!Capsule::schema()->hasTable($target['table'])) {
                continue;
            }

            $rows = Capsule::table($target['table'])
                ->where('user_id', '>', 0)
                ->where(function ($query) {
                    $query->where('service_id', 0)
                        ->orWhere('server_id', 0);
                })
                ->select('id', 'user_id', 'product_name', 'service_id', 'server_id', $target['ip_column'] . ' as binding_ip')
                ->get();

            foreach ($rows as $row) {
                $userId = (int) $row->user_id;
                if (!isset($serviceCache[$userId])) {
                    $serviceCache[$userId] = forward_get_user_services($userId, [], [], ['Active', 'Suspended'], 'all');
                }

                $service = forward_find_service_for_ip(
                    $serviceCache[$userId],
                    (string) ($row->binding_ip ?? ''),
                    (int) ($row->service_id ?? 0),
                    (int) ($row->server_id ?? 0),
                    (string) ($row->product_name ?? '')
                );
                if ($service === null) {
                    continue;
                }

                $updates = [];
                if ((int) ($row->service_id ?? 0) !== (int) ($service['service_id'] ?? 0)) {
                    $updates['service_id'] = (int) ($service['service_id'] ?? 0);
                }
                if ((int) ($row->server_id ?? 0) !== (int) ($service['server_id'] ?? 0)) {
                    $updates['server_id'] = (int) ($service['server_id'] ?? 0);
                }
                if (trim((string) ($row->product_name ?? '')) !== trim((string) ($service['product_name'] ?? ''))) {
                    $updates['product_name'] = trim((string) ($service['product_name'] ?? '')) !== ''
                        ? (string) $service['product_name']
                        : null;
                }

                if (!empty($updates)) {
                    Capsule::table($target['table'])
                        ->where('id', (int) $row->id)
                        ->update($updates);
                }
            }
        }
    } catch (Exception $e) {
        forward_log('backfill_local_service_bindings_error', [], $e->getMessage());
    }
}

function forward_backfill_remote_resource_ids()
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;

    try {
        if (Capsule::schema()->hasTable('mod_forward_rules') && Capsule::schema()->hasColumn('mod_forward_rules', 'remote_rule_id')) {
            Capsule::table('mod_forward_rules')
                ->whereNull('remote_rule_id')
                ->whereNotNull('forward_rule_id')
                ->update(['remote_rule_id' => Capsule::raw('forward_rule_id')]);
        }
        if (Capsule::schema()->hasTable('mod_forward_sites') && Capsule::schema()->hasColumn('mod_forward_sites', 'remote_site_id')) {
            Capsule::table('mod_forward_sites')
                ->whereNull('remote_site_id')
                ->whereNotNull('forward_site_id')
                ->update(['remote_site_id' => Capsule::raw('forward_site_id')]);
        }
    } catch (Exception $e) {
        forward_log('backfill_remote_resource_ids_error', [], $e->getMessage());
    }
}

function forward_backfill_endpoint_server_bindings()
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;

    $settings = forward_get_module_settings();
    if (empty(forward_parse_server_ip_server_map($settings['server_ip_server_map'] ?? ''))) {
        return;
    }

    try {
        $targets = [
            ['table' => 'mod_forward_rules', 'ip_column' => 'in_ip'],
            ['table' => 'mod_forward_sites', 'ip_column' => 'listen_ip'],
        ];

        foreach ($targets as $target) {
            if (!Capsule::schema()->hasTable($target['table'])) {
                continue;
            }

            $rows = Capsule::table($target['table'])
                ->where('server_id', 0)
                ->select('id', $target['ip_column'] . ' as listen_ip')
                ->get();

            foreach ($rows as $row) {
                $serverId = forward_infer_server_id_from_listen_ip($settings, (string) ($row->listen_ip ?? ''));
                if ($serverId <= 0) {
                    continue;
                }
                Capsule::table($target['table'])
                    ->where('id', (int) $row->id)
                    ->update(['server_id' => $serverId]);
            }
        }
    } catch (Exception $e) {
        forward_log('backfill_endpoint_server_bindings_error', [], $e->getMessage());
    }
}

function forward_api_error_message($status, $response = '', $decoded = null)
{
    $status = (int) $status;
    $raw = trim((string) $response);
    $message = '';

    if (is_array($decoded)) {
        $message = trim((string) ($decoded['error'] ?? $decoded['message'] ?? ''));
    }
    if ($message === '' && $raw !== '') {
        $message = $raw;
    }

    if ($status === 401 || strtolower($message) === 'unauthorized') {
        return 'Forward Bearer Token 认证失败：请确认 WHMCS 中填写的 Bearer Token 与 forward config.json 的 web_token 一致';
    }
    if ($status === 403) {
        return 'Forward API 拒绝访问：请检查 Token 权限或反向代理访问控制';
    }
    if ($message === '') {
        $message = 'HTTP ' . $status;
    }

    return 'Forward API 返回 HTTP ' . $status . ': ' . $message;
}

function forward_call_api_target(array $target, $path, $method = 'GET', array $payload = null)
{
    $endpoint = rtrim((string) ($target['endpoint'] ?? ''), '/');
    $token = trim((string) ($target['token'] ?? ''));
    $skipTlsVerify = !empty($target['skip_tls_verify']);

    if ($endpoint === '') {
        return ['success' => false, 'message' => '未配置 Forward API 地址'];
    }
    if ($token === '') {
        return ['success' => false, 'message' => '未配置 Forward Bearer Token'];
    }

    $url = $endpoint . $path;
    $ch = curl_init($url);
    $headers = [
        'Authorization: Bearer ' . $token,
        'Accept: application/json',
    ];

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, !$skipTlsVerify);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $skipTlsVerify ? 0 : 2);

    if ($payload !== null) {
        $json = json_encode($payload, JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            $jsonError = function_exists('json_last_error_msg') ? json_last_error_msg() : 'unknown error';
            curl_close($ch);
            return ['success' => false, 'message' => 'API 请求编码失败: ' . $jsonError];
        }
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
        $headers[] = 'Content-Type: application/json';
        $headers[] = 'Content-Length: ' . strlen($json);
    }

    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $response = curl_exec($ch);
    $errno = curl_errno($ch);
    $error = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($errno) {
        forward_log('api_curl_error', ['url' => $url, 'method' => $method], $error);
        return ['success' => false, 'message' => 'API 调用失败: ' . $error];
    }

    if ($response === false || $response === '') {
        return ($status >= 200 && $status < 300)
            ? ['success' => true, 'data' => null]
            : ['success' => false, 'message' => forward_api_error_message($status, '')];
    }

    $decoded = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ($status >= 200 && $status < 300)
            ? ['success' => true, 'data' => $response]
            : ['success' => false, 'message' => forward_api_error_message($status, $response)];
    }

    if ($status < 200 || $status >= 300) {
        $message = forward_api_error_message($status, $response, $decoded);
        return ['success' => false, 'message' => $message, 'data' => $decoded];
    }

    return ['success' => true, 'data' => $decoded];
}

function forward_call_api($path, $method = 'GET', array $payload = null, $serverId = 0)
{
    $config = forward_get_module_settings();
    $target = forward_get_api_target($config, (int) $serverId);
    if (!forward_api_target_enabled($target)) {
        return ['success' => false, 'message' => '未找到对应宿主机的 Forward 端点配置'];
    }
    return forward_call_api_target($target, $path, $method, $payload);
}

function forward_execute_db_write($logAction, callable $callback)
{
    try {
        $result = $callback();
        if ($result === false) {
            return ['success' => false, 'message' => '数据库操作未完成'];
        }
        return ['success' => true, 'result' => $result];
    } catch (Throwable $e) {
        forward_log($logAction, [], $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function forward_is_api_not_found_message($message)
{
    $message = strtolower(trim((string) $message));
    if ($message === '') {
        return false;
    }

    return strpos($message, 'not found') !== false || strpos($message, '不存在') !== false;
}

function forward_remote_toggle_resource($path, $id, $serverId, $currentEnabled = null)
{
    $id = (int) $id;
    if ($id <= 0) {
        return ['success' => false, 'message' => '无效的远端资源 ID'];
    }

    $api = forward_call_api($path . '?id=' . urlencode((string) $id), 'POST', null, $serverId);
    if (!$api['success']) {
        return ['success' => false, 'message' => $api['message']];
    }

    $data = is_array($api['data'] ?? null) ? $api['data'] : [];
    $enabled = array_key_exists('enabled', $data)
        ? (bool) $data['enabled']
        : ($currentEnabled === null ? null : !$currentEnabled);

    return ['success' => true, 'enabled' => $enabled];
}

function forward_remote_delete_resource($path, $id, $serverId)
{
    $id = (int) $id;
    if ($id <= 0) {
        return ['success' => true, 'state' => 'missing'];
    }

    $api = forward_call_api($path . '?id=' . urlencode((string) $id), 'DELETE', null, $serverId);
    if (!$api['success']) {
        if (forward_is_api_not_found_message($api['message'] ?? '')) {
            return ['success' => true, 'state' => 'missing'];
        }
        return ['success' => false, 'message' => $api['message']];
    }

    return ['success' => true, 'state' => 'deleted'];
}

function forward_best_effort_remote_delete_resource($path, $id, $serverId)
{
    $result = forward_remote_delete_resource($path, $id, $serverId);
    return !empty($result['success']);
}

function forward_remote_create_resource($path, $togglePath, array $payload, $serverId, $enabled = true)
{
    $api = forward_call_api($path, 'POST', $payload, $serverId);
    if (!$api['success']) {
        return ['success' => false, 'message' => $api['message']];
    }

    $data = is_array($api['data'] ?? null) ? $api['data'] : [];
    $remoteId = (int) ($data['id'] ?? 0);
    if ($remoteId <= 0) {
        return ['success' => false, 'message' => '后端返回了无效的资源 ID'];
    }

    if (!$enabled) {
        $toggle = forward_remote_toggle_resource($togglePath, $remoteId, $serverId, true);
        if (!$toggle['success']) {
            forward_best_effort_remote_delete_resource($path, $remoteId, $serverId);
            return ['success' => false, 'message' => '后端创建成功，但保持禁用状态失败：' . $toggle['message']];
        }
        if ($toggle['enabled'] !== false) {
            forward_best_effort_remote_delete_resource($path, $remoteId, $serverId);
            return ['success' => false, 'message' => '后端创建成功，但未能保持禁用状态'];
        }
    }

    return ['success' => true, 'id' => $remoteId];
}

function forward_get_remote_resource_snapshot(array $targets, $path)
{
    $snapshot = ['maps' => [], 'errors' => []];
    foreach ($targets as $key => $target) {
        $snapshot['maps'][$key] = [];
        $snapshot['errors'][$key] = '';

        $result = forward_call_api_target($target, $path, 'GET');
        if (!$result['success'] || !is_array($result['data'])) {
            $snapshot['errors'][$key] = !$result['success']
                ? (string) ($result['message'] ?? '远端返回异常')
                : '远端返回了无效的资源列表';
            continue;
        }

        $map = [];
        foreach ($result['data'] as $item) {
            if (isset($item['id'])) {
                $map[(int) $item['id']] = $item;
            }
        }
        $snapshot['maps'][$key] = $map;
    }

    return $snapshot;
}

function forward_get_remote_resource_maps(array $targets, $path)
{
    $snapshot = forward_get_remote_resource_snapshot($targets, $path);
    return $snapshot['maps'];
}

function forward_status_meta(array $remote = null, $localStatus = 'active', $remoteError = '', $expectsRemote = false)
{
    if ($remoteError !== '') {
        return ['text' => '远端异常', 'class' => 'warning'];
    }

    if ($remote === null) {
        if ($expectsRemote) {
            return ['text' => '远端缺失', 'class' => 'danger'];
        }
        if ($localStatus === 'inactive') {
            return ['text' => '已禁用', 'class' => 'default'];
        }
        return ['text' => '已启用', 'class' => 'success'];
    }

    if (isset($remote['enabled']) && !$remote['enabled']) {
        return ['text' => '已禁用', 'class' => 'default'];
    }

    $status = (string) ($remote['status'] ?? 'stopped');
    switch ($status) {
        case 'running':
            return ['text' => '运行中', 'class' => 'success'];
        case 'error':
            return ['text' => '异常', 'class' => 'danger'];
        case 'draining':
            return ['text' => '更新中', 'class' => 'warning'];
        case 'stopped':
        default:
            return ['text' => '已停止', 'class' => 'default'];
    }
}

function forward_build_rule_payload_from_rule(array $rule, $remoteId = 0)
{
    $payload = [
        'in_interface' => $rule['in_interface'],
        'in_ip' => $rule['in_ip'],
        'in_port' => $rule['in_port'],
        'out_interface' => $rule['out_interface'],
        'out_ip' => $rule['out_ip'],
        'out_source_ip' => $rule['out_source_ip'],
        'out_port' => $rule['out_port'],
        'protocol' => $rule['protocol'],
        'remark' => $rule['rule_name'],
        'tag' => $rule['tag'],
        'transparent' => $rule['transparent'],
    ];
    if ((int) $remoteId > 0) {
        $payload['id'] = (int) $remoteId;
    }
    return $payload;
}

function forward_build_rule_payload_from_record($record, $remoteId = null)
{
    return forward_build_rule_payload_from_rule([
        'in_interface' => forward_data_get($record, 'in_interface', ''),
        'in_ip' => forward_data_get($record, 'in_ip', ''),
        'in_port' => (int) forward_data_get($record, 'in_port', 0),
        'out_interface' => forward_data_get($record, 'out_interface', ''),
        'out_ip' => forward_data_get($record, 'out_ip', ''),
        'out_source_ip' => forward_data_get($record, 'out_source_ip', ''),
        'out_port' => (int) forward_data_get($record, 'out_port', 0),
        'protocol' => forward_data_get($record, 'protocol', ''),
        'rule_name' => forward_data_get($record, 'rule_name', ''),
        'tag' => forward_data_get($record, 'tag', ''),
        'transparent' => (bool) forward_data_get($record, 'transparent', false),
    ], $remoteId === null ? forward_get_rule_remote_id($record) : $remoteId);
}

function forward_build_site_payload_from_site(array $site, $remoteId = 0)
{
    $payload = [
        'domain' => $site['domain'],
        'listen_interface' => $site['listen_interface'],
        'listen_ip' => $site['listen_ip'],
        'backend_ip' => $site['backend_ip'],
        'backend_source_ip' => $site['backend_source_ip'],
        'backend_http_port' => $site['backend_http_port'],
        'backend_https_port' => $site['backend_https_port'],
        'tag' => $site['tag'],
        'transparent' => $site['transparent'],
    ];
    if ((int) $remoteId > 0) {
        $payload['id'] = (int) $remoteId;
    }
    return $payload;
}

function forward_build_site_payload_from_record($record, $remoteId = null)
{
    return forward_build_site_payload_from_site([
        'domain' => forward_data_get($record, 'domain', ''),
        'listen_interface' => forward_data_get($record, 'listen_interface', ''),
        'listen_ip' => forward_data_get($record, 'listen_ip', ''),
        'backend_ip' => forward_data_get($record, 'backend_ip', ''),
        'backend_source_ip' => forward_data_get($record, 'backend_source_ip', ''),
        'backend_http_port' => (int) forward_data_get($record, 'backend_http_port', 0),
        'backend_https_port' => (int) forward_data_get($record, 'backend_https_port', 0),
        'tag' => forward_data_get($record, 'tag', ''),
        'transparent' => (bool) forward_data_get($record, 'transparent', false),
    ], $remoteId === null ? forward_get_site_remote_id($record) : $remoteId);
}

function forward_get_remote_rule_maps(array $settings, array $serverIds)
{
    return forward_get_remote_resource_maps(forward_collect_api_targets($settings, $serverIds), '/api/rules');
}

function forward_get_remote_rule_snapshot(array $settings, array $serverIds)
{
    return forward_get_remote_resource_snapshot(forward_collect_api_targets($settings, $serverIds), '/api/rules');
}

function forward_get_local_rules($userId = null, $refreshRemote = true)
{
    $settings = forward_get_module_settings();
    $query = Capsule::table('mod_forward_rules')->orderBy('created_at', 'desc');
    if ($userId !== null) {
        $query->where('user_id', (int) $userId);
    }

    $rows = $query->get();
    $serverIds = [];
    foreach ($rows as $row) {
        $serverIds[] = forward_resolve_record_server_id($row, $settings, 'in_ip');
    }
    $remoteSnapshot = $refreshRemote
        ? forward_get_remote_rule_snapshot($settings, $serverIds)
        : ['maps' => [], 'errors' => []];
    $remoteMaps = $remoteSnapshot['maps'];
    $remoteErrors = $remoteSnapshot['errors'];
    $result = [];

    foreach ($rows as $row) {
        $resolvedServerId = forward_resolve_record_server_id($row, $settings, 'in_ip');
        $target = forward_get_api_target($settings, $resolvedServerId);
        $remoteId = forward_get_rule_remote_id($row);
        $remoteKey = $target['key'] ?? '';
        $remoteError = '';
        if (forward_api_target_enabled($target)) {
            $remoteError = (string) ($remoteErrors[$remoteKey] ?? '');
        } elseif ($remoteId > 0) {
            $remoteError = '当前宿主机未配置 Forward 端点';
        }
        $remote = null;
        if (
            $remoteId > 0
            && forward_api_target_enabled($target)
            && isset($remoteMaps[$remoteKey][$remoteId])
        ) {
            $remote = $remoteMaps[$remoteKey][$remoteId];
        }
        $statusMeta = forward_status_meta($remote, $row->status, $remoteError, $refreshRemote && $remoteId > 0);
        $result[] = [
            'id' => (int) $row->id,
            'forward_rule_id' => $remoteId,
            'remote_rule_id' => $remoteId,
            'user_id' => (int) $row->user_id,
            'product_name' => $row->product_name ?: '',
            'server_id' => $resolvedServerId,
            'service_id' => (int) ($row->service_id ?? 0),
            'server_label' => forward_get_server_label($resolvedServerId),
            'rule_name' => $row->rule_name,
            'in_interface' => $row->in_interface ?: '',
            'in_ip' => $row->in_ip,
            'in_port' => (int) $row->in_port,
            'in_endpoint' => forward_format_endpoint($row->in_ip, (int) $row->in_port),
            'out_interface' => $row->out_interface ?: '',
            'out_ip' => $row->out_ip,
            'out_port' => (int) $row->out_port,
            'out_endpoint' => forward_format_endpoint($row->out_ip, (int) $row->out_port),
            'out_source_ip' => $row->out_source_ip ?: '',
            'protocol' => $row->protocol,
            'tag' => $row->tag ?: '',
            'transparent' => (bool) $row->transparent,
            'status' => $row->status,
            'description' => $row->description ?: '',
            'created_at' => $row->created_at,
            'updated_at' => $row->updated_at,
            'remote_status' => $remote['status'] ?? '',
            'remote_error' => $remoteError,
            'enabled' => isset($remote['enabled']) ? (bool) $remote['enabled'] : ($row->status === 'active'),
            'status_text' => $statusMeta['text'],
            'status_class' => $statusMeta['class'],
        ];
    }

    return $result;
}

function forward_get_local_rule_record($ruleId)
{
    return Capsule::table('mod_forward_rules')->where('id', (int) $ruleId)->first();
}

function forward_has_remote_conflict($listenIp, $inPort, $protocol, $excludeRemoteRuleId = 0, $serverId = 0)
{
    $settings = forward_get_module_settings();
    $target = forward_get_api_target($settings, (int) $serverId);
    if (!forward_api_target_enabled($target)) {
        return false;
    }
    $remoteMaps = forward_get_remote_rule_maps($settings, [(int) $serverId]);
    $remoteMap = $remoteMaps[$target['key']] ?? [];
    $conflictProtocols = forward_protocol_conflicts($protocol);
    foreach ($remoteMap as $id => $rule) {
        if ($excludeRemoteRuleId > 0 && (int) $id === (int) $excludeRemoteRuleId) {
            continue;
        }
        $ruleInIP = (string) ($rule['in_ip'] ?? '');
        $ruleInPort = (int) ($rule['in_port'] ?? 0);
        $ruleProtocol = forward_normalize_protocol($rule['protocol'] ?? '');
        if (
            forward_ips_conflict($ruleInIP, $listenIp)
            && $ruleInPort === (int) $inPort
            && in_array($ruleProtocol, $conflictProtocols, true)
        ) {
            return true;
        }
    }
    return false;
}

function forward_get_local_rule($ruleId, $userId = null)
{
    $query = Capsule::table('mod_forward_rules')->where('id', (int) $ruleId);
    if ($userId !== null) {
        $query->where('user_id', (int) $userId);
    }
    $row = $query->first();
    if (!$row) {
        return null;
    }

    $settings = forward_get_module_settings();
    $resolvedServerId = forward_resolve_record_server_id($row, $settings, 'in_ip');
    $target = forward_get_api_target($settings, $resolvedServerId);
    $remoteId = forward_get_rule_remote_id($row);
    $remoteSnapshot = forward_get_remote_rule_snapshot($settings, [$resolvedServerId]);
    $remoteMaps = $remoteSnapshot['maps'];
    $remoteErrors = $remoteSnapshot['errors'];
    $remoteKey = $target['key'] ?? '';
    $remoteError = '';
    if (forward_api_target_enabled($target)) {
        $remoteError = (string) ($remoteErrors[$remoteKey] ?? '');
    } elseif ($remoteId > 0) {
        $remoteError = '当前宿主机未配置 Forward 端点';
    }
    $remote = ($remoteId > 0 && forward_api_target_enabled($target) && isset($remoteMaps[$remoteKey][$remoteId]))
        ? $remoteMaps[$remoteKey][$remoteId]
        : null;
    $statusMeta = forward_status_meta($remote, $row->status, $remoteError, $remoteId > 0);

    return [
        'id' => (int) $row->id,
        'forward_rule_id' => $remoteId,
        'remote_rule_id' => $remoteId,
        'user_id' => (int) $row->user_id,
        'product_name' => $row->product_name ?: '',
        'server_id' => $resolvedServerId,
        'service_id' => (int) ($row->service_id ?? 0),
        'server_label' => forward_get_server_label($resolvedServerId),
        'rule_name' => $row->rule_name,
        'in_interface' => $row->in_interface ?: '',
        'in_ip' => $row->in_ip,
        'in_port' => (int) $row->in_port,
        'in_endpoint' => forward_format_endpoint($row->in_ip, (int) $row->in_port),
        'out_interface' => $row->out_interface ?: '',
        'out_ip' => $row->out_ip,
        'out_port' => (int) $row->out_port,
        'out_endpoint' => forward_format_endpoint($row->out_ip, (int) $row->out_port),
        'out_source_ip' => $row->out_source_ip ?: '',
        'protocol' => $row->protocol,
        'tag' => $row->tag ?: '',
        'transparent' => (bool) $row->transparent,
        'status' => $row->status,
        'description' => $row->description ?: '',
        'remote_error' => $remoteError,
        'status_text' => $statusMeta['text'],
        'status_class' => $statusMeta['class'],
    ];
}

function forward_validate_rule_input(array $data, array $settings, $isClient = false, $excludeLocalRuleId = 0, $excludeRemoteRuleId = 0, array $allowedListenIps = null, $targetServerId = 0, array $defaults = [])
{
    $defaults = array_merge([
        'in_interface' => trim((string) ($settings['in_interface'] ?? '')),
        'out_interface' => trim((string) ($settings['out_interface'] ?? '')),
        'tag' => trim((string) ($settings['default_tag'] ?? '')),
        'transparent' => forward_is_enabled_value($settings['transparent_mode'] ?? 'off'),
        'out_source_ip' => '',
    ], $defaults);
    $listenIps = $allowedListenIps !== null ? array_values(array_unique($allowedListenIps)) : forward_get_all_server_ips($settings);
    if (empty($listenIps)) {
        return ['success' => false, 'message' => '当前服务未配置可用的入口 IP'];
    }
    $listenIp = forward_pick_listen_ip($data['listen_ip'] ?? $data['in_ip'] ?? '', $listenIps);
    if ($listenIp === '') {
        return ['success' => false, 'message' => '入口 IP 不在当前服务允许范围内'];
    }

    $ruleName = trim((string) ($data['rule_name'] ?? ''));
    if ($ruleName === '' || forward_strlen($ruleName) < 2) {
        return ['success' => false, 'message' => '规则名称至少需要 2 个字符'];
    }
    if (forward_strlen($ruleName) > 100) {
        return ['success' => false, 'message' => '规则名称不能超过 100 个字符'];
    }

    $outIp = forward_normalize_ip_literal($data['internal_ip'] ?? $data['out_ip'] ?? '');
    if ($outIp === '') {
        return ['success' => false, 'message' => '目标 IP 必须是有效的 IP 地址'];
    }

    $outPort = (int) ($data['internal_port'] ?? $data['out_port'] ?? 0);
    if ($outPort < 1 || $outPort > 65535) {
        return ['success' => false, 'message' => '目标端口必须在 1-65535 之间'];
    }

    $inPort = (int) ($data['external_port'] ?? $data['in_port'] ?? 0);
    $listenPortRange = forward_get_listen_port_range($settings, $isClient);
    if ($inPort < (int) $listenPortRange['min'] || $inPort > (int) $listenPortRange['max']) {
        return ['success' => false, 'message' => '入口端口必须在 ' . $listenPortRange['text'] . ' 之间'];
    }

    $allowedProtocols = forward_protocol_options($settings['allowed_protocols'] ?? 'tcp+udp');
    $protocol = forward_normalize_protocol($data['protocol'] ?? '');
    if ($protocol === '' || !in_array($protocol, $allowedProtocols, true)) {
        return ['success' => false, 'message' => '不支持的协议类型'];
    }

    $transparent = forward_resolve_checkbox_value($data, 'transparent', !empty($defaults['transparent']));
    $normalizedSourceIP = forward_normalize_optional_ip($data['out_source_ip'] ?? ($defaults['out_source_ip'] ?? ''));
    if (!$normalizedSourceIP['success']) {
        return ['success' => false, 'message' => '回源 IP ' . $normalizedSourceIP['message']];
    }
    $outSourceIP = $transparent ? '' : $normalizedSourceIP['value'];

    if ($transparent && !forward_ip_pair_is_pure_ipv4($listenIp, $outIp)) {
        return ['success' => false, 'message' => '透传当前仅支持 IPv4 入口与目标 IP 组合'];
    }
    if ($outSourceIP !== '' && forward_ip_family($outSourceIP) !== forward_ip_family($outIp)) {
        return ['success' => false, 'message' => '回源 IP 必须与目标 IP 地址族一致'];
    }

    $conflictQuery = Capsule::table('mod_forward_rules')
        ->where('server_id', (int) $targetServerId)
        ->where('in_port', $inPort)
        ->whereIn('protocol', forward_protocol_conflicts($protocol));

    if ($excludeLocalRuleId > 0) {
        $conflictQuery->where('id', '!=', (int) $excludeLocalRuleId);
    }

    $localConflicts = $conflictQuery->select('in_ip')->get();
    foreach ($localConflicts as $conflict) {
        if (forward_ips_conflict($listenIp, $conflict->in_ip ?? '')) {
            return ['success' => false, 'message' => '该入口端口已在模块中被占用'];
        }
    }

    if (forward_has_remote_conflict($listenIp, $inPort, $protocol, $excludeRemoteRuleId, $targetServerId)) {
        return ['success' => false, 'message' => '该入口端口已在 forward 中被其他规则占用'];
    }

    $productName = trim((string) ($data['product_name'] ?? ''));
    if (forward_strlen($productName) > 100) {
        return ['success' => false, 'message' => '产品名称不能超过 100 个字符'];
    }

    $description = trim((string) ($data['description'] ?? ''));
    if (forward_strlen($description) > 2000) {
        return ['success' => false, 'message' => '描述不能超过 2000 个字符'];
    }

    return [
        'success' => true,
        'data' => [
            'rule_name' => $ruleName,
            'in_interface' => trim((string) ($data['in_interface'] ?? $defaults['in_interface'])),
            'in_ip' => $listenIp,
            'listen_ips' => $listenIps,
            'in_port' => $inPort,
            'out_interface' => trim((string) ($data['out_interface'] ?? $defaults['out_interface'])),
            'out_ip' => $outIp,
            'out_port' => $outPort,
            'out_source_ip' => $outSourceIP,
            'protocol' => $protocol,
            'tag' => trim((string) ($data['tag'] ?? $defaults['tag'])),
            'transparent' => $transparent,
            'description' => $description,
            'product_name' => $productName,
        ],
    ];
}

function forward_create_rule(array $data, $userId = 0, $isClient = false)
{
    $settings = forward_get_module_settings();
    $clientPermissions = forward_client_permissions($settings);
    $service = null;
    $allowedListenIps = null;
    $targetServerId = 0;
    if ($isClient) {
        $allowedProducts = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
        $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
        $services = forward_get_user_services($userId, $allowedProducts, $allowedClientIps, ['Active'], forward_client_service_ip_family($settings));
        $service = forward_find_service_for_ip(
            $services,
            trim((string) ($data['internal_ip'] ?? $data['out_ip'] ?? '')),
            (int) ($data['service_id'] ?? 0),
            (int) ($data['server_id'] ?? 0),
            (string) ($data['product_name'] ?? '')
        );
        if ($service === null) {
            return ['success' => false, 'message' => '目标 IP 不属于当前用户可用的服务'];
        }
        $allowedListenIps = forward_get_allowed_server_ips($settings, (int) ($service['server_id'] ?? 0));
        if (empty($allowedListenIps)) {
            return ['success' => false, 'message' => '该服务所属宿主机未配置入口 IP'];
        }
        $targetServerId = (int) ($service['server_id'] ?? 0);
        $data['in_interface'] = trim((string) ($settings['in_interface'] ?? ''));
        $data['out_interface'] = trim((string) ($settings['out_interface'] ?? ''));
        $data['tag'] = trim((string) ($settings['default_tag'] ?? ''));
        $data['transparent'] = forward_is_enabled_value($settings['transparent_mode'] ?? 'off') ? '1' : '0';
        $data['out_source_ip'] = '';
        if (empty($clientPermissions['rule']['listen_ip'])) {
            $data['listen_ip'] = '';
        }
        if (empty($clientPermissions['rule']['protocol'])) {
            $data['protocol'] = forward_client_default_rule_protocol($settings);
        }
        if (empty($clientPermissions['rule']['description'])) {
            $data['description'] = '';
        }
    }

    if (!$isClient) {
        $serverResolution = forward_resolve_target_server_id(
            $settings,
            $data['listen_ip'] ?? $data['in_ip'] ?? '',
            (int) ($data['server_id'] ?? 0)
        );
        if (!$serverResolution['success']) {
            return $serverResolution;
        }
        $targetServerId = (int) ($serverResolution['server_id'] ?? 0);
    }

    $validated = forward_validate_rule_input($data, $settings, $isClient, 0, 0, $allowedListenIps, $targetServerId);
    if (!$validated['success']) {
        return $validated;
    }

    $rule = $validated['data'];

    if ($isClient) {
        $sync = forward_sync_quota_group_before_create($services, $settings, $service, 'rules', '端口规则');
        if (empty($sync['success'])) {
            return $sync;
        }

        $quota = forward_product_rule_quota($settings, $userId, $service);
        if (empty($quota['can_create'])) {
            $productLabel = trim((string) ($service['product_name'] ?? ''));
            $productText = $productLabel !== '' ? ('产品“' . $productLabel . '”') : '当前产品';
            return [
                'success' => false,
                'message' => $productText . '已达到端口规则数量限制（' . (int) $quota['count'] . '/' . (int) $quota['limit'] . '）',
            ];
        }

        $rule['product_name'] = $service['product_name'];
    }

    $payload = forward_build_rule_payload_from_rule($rule);
    $remoteCreate = forward_remote_create_resource('/api/rules', '/api/rules/toggle', $payload, $targetServerId, true);
    if (!$remoteCreate['success']) {
        return ['success' => false, 'message' => '后端创建规则失败：' . $remoteCreate['message']];
    }

    $remoteId = (int) ($remoteCreate['id'] ?? 0);
    $insert = forward_execute_db_write('create_rule_local_insert_error', function () use ($rule, $remoteId, $userId, $service, $targetServerId) {
        return Capsule::table('mod_forward_rules')->insert([
            'forward_rule_id' => null,
            'remote_rule_id' => $remoteId > 0 ? $remoteId : null,
            'user_id' => (int) $userId,
            'product_name' => $rule['product_name'] ?: null,
            'server_id' => is_array($service) ? (int) ($service['server_id'] ?? 0) : $targetServerId,
            'service_id' => is_array($service) ? (int) ($service['service_id'] ?? 0) : 0,
            'rule_name' => $rule['rule_name'],
            'in_interface' => $rule['in_interface'],
            'in_ip' => $rule['in_ip'],
            'in_port' => $rule['in_port'],
            'out_interface' => $rule['out_interface'],
            'out_ip' => $rule['out_ip'],
            'out_port' => $rule['out_port'],
            'out_source_ip' => $rule['out_source_ip'],
            'protocol' => $rule['protocol'],
            'tag' => $rule['tag'],
            'transparent' => $rule['transparent'] ? 1 : 0,
            'status' => 'active',
            'description' => $rule['description'],
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s'),
        ]);
    });
    if (!$insert['success']) {
        $rolledBack = forward_best_effort_remote_delete_resource('/api/rules', $remoteId, $targetServerId);
        $message = '本地写入规则失败：' . $insert['message'];
        $message .= $rolledBack ? '；已回滚远端规则' : '；远端回滚失败，请手动删除已创建的远端规则';
        return ['success' => false, 'message' => $message];
    }

    return ['success' => true, 'message' => '规则创建成功'];
}

function forward_update_rule(array $data, $userId = null)
{
    $ruleId = (int) ($data['rule_id'] ?? 0);
    if ($ruleId <= 0) {
        return ['success' => false, 'message' => '无效的规则 ID'];
    }

    $record = Capsule::table('mod_forward_rules')->where('id', $ruleId);
    if ($userId !== null) {
        $record->where('user_id', (int) $userId);
    }
    $existing = $record->first();
    if (!$existing) {
        return ['success' => false, 'message' => '规则不存在'];
    }

    $settings = forward_get_module_settings();
    $clientPermissions = forward_client_permissions($settings);
    if ($userId !== null) {
        $data['internal_ip'] = $existing->out_ip;
        $data['in_interface'] = $existing->in_interface ?: trim((string) ($settings['in_interface'] ?? ''));
        $data['out_interface'] = $existing->out_interface ?: trim((string) ($settings['out_interface'] ?? ''));
        $data['tag'] = $existing->tag ?: trim((string) ($settings['default_tag'] ?? ''));
        $data['transparent'] = !empty($existing->transparent) ? '1' : '0';
        $data['out_source_ip'] = $existing->out_source_ip ?: '';
    }
    $existingServerId = forward_resolve_record_server_id($existing, $settings, 'in_ip');
    $existingRemoteId = forward_get_rule_remote_id($existing);
    $service = null;
    $allowedListenIps = null;
    $targetServerId = $existingServerId;
    if ($userId !== null) {
        $allowedProducts = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
        $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
        $services = forward_get_user_services($userId, $allowedProducts, $allowedClientIps, ['Active'], forward_client_service_ip_family($settings));
        $service = forward_find_service_for_ip(
            $services,
            trim((string) ($data['internal_ip'] ?? $data['out_ip'] ?? '')),
            (int) ($existing->service_id ?? 0) > 0 ? (int) ($existing->service_id ?? 0) : (int) ($data['service_id'] ?? 0),
            $existingServerId > 0 ? $existingServerId : (int) ($data['server_id'] ?? 0),
            (string) ($existing->product_name ?? '')
        );
        if ($service === null) {
            return ['success' => false, 'message' => '目标 IP 不属于当前用户可用的服务'];
        }
        $allowedListenIps = forward_get_allowed_server_ips($settings, (int) ($service['server_id'] ?? 0));
        if (empty($allowedListenIps)) {
            return ['success' => false, 'message' => '该服务所属宿主机未配置入口 IP'];
        }
        $targetServerId = (int) ($service['server_id'] ?? 0);
        if (empty($clientPermissions['rule']['listen_ip'])) {
            $data['listen_ip'] = forward_client_locked_listen_ip($existing->in_ip ?? '', $allowedListenIps);
        }
        if (empty($clientPermissions['rule']['protocol'])) {
            $data['protocol'] = (string) ($existing->protocol ?? forward_client_default_rule_protocol($settings));
        }
        if (empty($clientPermissions['rule']['description'])) {
            $data['description'] = (string) ($existing->description ?? '');
        }
    } else {
        $serverResolution = forward_resolve_target_server_id(
            $settings,
            $data['listen_ip'] ?? $data['in_ip'] ?? $existing->in_ip ?? '',
            (int) ($data['server_id'] ?? $existingServerId)
        );
        if (!$serverResolution['success']) {
            return $serverResolution;
        }
        $targetServerId = (int) ($serverResolution['server_id'] ?? 0);
    }

    $validated = forward_validate_rule_input(
        $data,
        $settings,
        $userId !== null,
        $ruleId,
        ($existingRemoteId > 0 && $targetServerId === $existingServerId) ? $existingRemoteId : 0,
        $allowedListenIps,
        $targetServerId,
        [
            'in_interface' => $existing->in_interface ?: trim((string) ($settings['in_interface'] ?? '')),
            'out_interface' => $existing->out_interface ?: trim((string) ($settings['out_interface'] ?? '')),
            'tag' => $existing->tag ?: trim((string) ($settings['default_tag'] ?? '')),
            'transparent' => (bool) $existing->transparent,
            'out_source_ip' => $existing->out_source_ip ?: '',
        ]
    );
    if (!$validated['success']) {
        return $validated;
    }

    $rule = $validated['data'];
    if ($userId !== null) {
        $rule['product_name'] = $service['product_name'];
    }

    $sameRemote = $existingRemoteId > 0 && $targetServerId === $existingServerId;
    $desiredEnabled = $existing->status !== 'inactive';
    $updateValues = [
        'forward_rule_id' => null,
        'remote_rule_id' => null,
        'product_name' => $rule['product_name'] ?: null,
        'server_id' => $userId !== null
            ? (is_array($service) ? (int) ($service['server_id'] ?? 0) : 0)
            : $targetServerId,
        'service_id' => $userId !== null
            ? (is_array($service) ? (int) ($service['service_id'] ?? 0) : 0)
            : (int) ($data['service_id'] ?? $existing->service_id ?? 0),
        'rule_name' => $rule['rule_name'],
        'in_interface' => $rule['in_interface'],
        'in_ip' => $rule['in_ip'],
        'in_port' => $rule['in_port'],
        'out_interface' => $rule['out_interface'],
        'out_ip' => $rule['out_ip'],
        'out_port' => $rule['out_port'],
        'out_source_ip' => $rule['out_source_ip'],
        'protocol' => $rule['protocol'],
        'tag' => $rule['tag'],
        'transparent' => $rule['transparent'] ? 1 : 0,
        'description' => $rule['description'],
        'updated_at' => date('Y-m-d H:i:s'),
    ];
    $restoreValues = [
        'forward_rule_id' => forward_data_get($existing, 'forward_rule_id') ?: null,
        'remote_rule_id' => $existingRemoteId > 0 ? $existingRemoteId : null,
        'product_name' => $existing->product_name ?: null,
        'server_id' => (int) ($existing->server_id ?? 0),
        'service_id' => (int) ($existing->service_id ?? 0),
        'rule_name' => $existing->rule_name,
        'in_interface' => $existing->in_interface ?: '',
        'in_ip' => $existing->in_ip,
        'in_port' => (int) $existing->in_port,
        'out_interface' => $existing->out_interface ?: '',
        'out_ip' => $existing->out_ip,
        'out_port' => (int) $existing->out_port,
        'out_source_ip' => $existing->out_source_ip ?: '',
        'protocol' => $existing->protocol,
        'tag' => $existing->tag ?: '',
        'transparent' => !empty($existing->transparent) ? 1 : 0,
        'status' => $existing->status ?: 'active',
        'description' => $existing->description ?: '',
        'updated_at' => date('Y-m-d H:i:s'),
    ];

    if ($sameRemote) {
        $payload = forward_build_rule_payload_from_rule($rule, $existingRemoteId);
        $api = forward_call_api('/api/rules', 'PUT', $payload, $targetServerId);
        if (!$api['success'] && !forward_is_api_not_found_message($api['message'] ?? '')) {
            return ['success' => false, 'message' => '后端更新规则失败：' . $api['message']];
        }
        if (!empty($api['success'])) {
            $updateValues['remote_rule_id'] = $existingRemoteId > 0 ? $existingRemoteId : null;
            $dbUpdate = forward_execute_db_write('update_rule_local_update_error', function () use ($ruleId, $updateValues) {
                return Capsule::table('mod_forward_rules')->where('id', $ruleId)->update($updateValues);
            });
            if (!$dbUpdate['success']) {
                $restoreApi = forward_call_api('/api/rules', 'PUT', forward_build_rule_payload_from_record($existing), $existingServerId);
                $message = '本地更新规则失败：' . $dbUpdate['message'];
                $message .= !empty($restoreApi['success'])
                    ? '；已回滚远端规则'
                    : '；远端回滚失败：' . ($restoreApi['message'] ?? '未知错误');
                return ['success' => false, 'message' => $message];
            }

            return ['success' => true, 'message' => '规则更新成功'];
        }

        $sameRemote = false;
    }

    $newRemote = forward_remote_create_resource(
        '/api/rules',
        '/api/rules/toggle',
        forward_build_rule_payload_from_rule($rule),
        $targetServerId,
        $desiredEnabled
    );
    if (!$newRemote['success']) {
        return ['success' => false, 'message' => '后端更新规则失败：' . $newRemote['message']];
    }

    $remoteId = (int) ($newRemote['id'] ?? 0);
    $updateValues['remote_rule_id'] = $remoteId > 0 ? $remoteId : null;
    $dbUpdate = forward_execute_db_write('update_rule_local_update_error', function () use ($ruleId, $updateValues) {
        return Capsule::table('mod_forward_rules')->where('id', $ruleId)->update($updateValues);
    });
    if (!$dbUpdate['success']) {
        $rolledBack = forward_best_effort_remote_delete_resource('/api/rules', $remoteId, $targetServerId);
        $message = '本地更新规则失败：' . $dbUpdate['message'];
        $message .= $rolledBack ? '；已回滚新建的远端规则' : '；新建的远端规则回滚失败，请手动清理';
        return ['success' => false, 'message' => $message];
    }

    if ($existingRemoteId > 0 && $targetServerId !== $existingServerId) {
        $cleanup = forward_remote_delete_resource('/api/rules', $existingRemoteId, $existingServerId);
        if (!$cleanup['success']) {
            $restoreLocal = forward_execute_db_write('update_rule_local_restore_error', function () use ($ruleId, $restoreValues) {
                return Capsule::table('mod_forward_rules')->where('id', $ruleId)->update($restoreValues);
            });
            $rolledBackRemote = forward_best_effort_remote_delete_resource('/api/rules', $remoteId, $targetServerId);

            $message = '旧 Forward 端删除规则失败：' . $cleanup['message'];
            $message .= $restoreLocal['success'] ? '；已回滚本地配置' : '；本地回滚失败：' . $restoreLocal['message'];
            $message .= $rolledBackRemote ? '，并已清理新 Forward 端规则' : '，但新 Forward 端规则清理失败，请手动核对';
            return ['success' => false, 'message' => $message];
        }
    }

    return ['success' => true, 'message' => '规则更新成功'];
}

function forward_toggle_rule($ruleId, $userId = null)
{
    $query = Capsule::table('mod_forward_rules')->where('id', (int) $ruleId);
    if ($userId !== null) {
        $query->where('user_id', (int) $userId);
    }
    $existing = $query->first();
    if (!$existing) {
        return ['success' => false, 'message' => '规则不存在'];
    }

    $settings = forward_get_module_settings();
    $serverId = forward_resolve_record_server_id($existing, $settings, 'in_ip');
    $remoteId = forward_get_rule_remote_id($existing);
    $enabled = $existing->status !== 'inactive';
    $currentEnabled = $enabled;
    if ($remoteId > 0) {
        $toggle = forward_remote_toggle_resource('/api/rules/toggle', $remoteId, $serverId, $currentEnabled);
        if (!$toggle['success']) {
            return ['success' => false, 'message' => '后端切换规则状态失败：' . $toggle['message']];
        }
        $enabled = $toggle['enabled'] === null ? !$currentEnabled : (bool) $toggle['enabled'];
    } else {
        $enabled = !$enabled;
    }

    $dbUpdate = forward_execute_db_write('toggle_rule_local_update_error', function () use ($ruleId, $enabled) {
        return Capsule::table('mod_forward_rules')
            ->where('id', (int) $ruleId)
            ->update([
            'status' => $enabled ? 'active' : 'inactive',
            'updated_at' => date('Y-m-d H:i:s'),
            ]);
    });
    if (!$dbUpdate['success']) {
        if ($remoteId > 0) {
            $rollback = forward_remote_toggle_resource('/api/rules/toggle', $remoteId, $serverId, $enabled);
            $message = '本地切换规则状态失败：' . $dbUpdate['message'];
            $message .= $rollback['success'] ? '；已回滚远端状态' : '；远端状态回滚失败：' . $rollback['message'];
            return ['success' => false, 'message' => $message];
        }
        return ['success' => false, 'message' => '本地切换规则状态失败：' . $dbUpdate['message']];
    }

    return [
        'success' => true,
        'message' => $enabled ? '规则已启用' : '规则已禁用',
        'enabled' => $enabled,
    ];
}

function forward_delete_rule($ruleId, $userId = null)
{
    $query = Capsule::table('mod_forward_rules')->where('id', (int) $ruleId);
    if ($userId !== null) {
        $query->where('user_id', (int) $userId);
    }
    $existing = $query->first();
    if (!$existing) {
        return ['success' => false, 'message' => '规则不存在'];
    }

    $settings = forward_get_module_settings();
    $serverId = forward_resolve_record_server_id($existing, $settings, 'in_ip');
    $remoteId = forward_get_rule_remote_id($existing);
    $remoteDelete = ['success' => true, 'state' => 'missing'];
    if ($remoteId > 0) {
        $remoteDelete = forward_remote_delete_resource('/api/rules', $remoteId, $serverId);
        if (!$remoteDelete['success']) {
            return ['success' => false, 'message' => '后端删除规则失败：' . $remoteDelete['message']];
        }
    }

    $dbDelete = forward_execute_db_write('delete_rule_local_error', function () use ($ruleId) {
        return Capsule::table('mod_forward_rules')->where('id', (int) $ruleId)->delete();
    });
    if (!$dbDelete['success']) {
        $message = '本地删除规则失败：' . $dbDelete['message'];
        if (($remoteDelete['state'] ?? '') === 'deleted') {
            $recreate = forward_remote_create_resource(
                '/api/rules',
                '/api/rules/toggle',
                forward_build_rule_payload_from_record($existing, 0),
                $serverId,
                $existing->status !== 'inactive'
            );
            if ($recreate['success']) {
                $newRemoteId = (int) ($recreate['id'] ?? 0);
                $repair = forward_execute_db_write('delete_rule_local_rebind_error', function () use ($ruleId, $newRemoteId) {
                    return Capsule::table('mod_forward_rules')
                        ->where('id', (int) $ruleId)
                        ->update([
                            'forward_rule_id' => null,
                            'remote_rule_id' => $newRemoteId > 0 ? $newRemoteId : null,
                            'updated_at' => date('Y-m-d H:i:s'),
                        ]);
                });
                $message .= $repair['success']
                    ? '；已重建远端规则以保持一致'
                    : '；已重建远端规则，但本地回写新的远端 ID 失败：' . $repair['message'];
            } else {
                $message .= '；远端规则已删除，但重建失败：' . $recreate['message'];
            }
        }
        return ['success' => false, 'message' => $message];
    }

    return ['success' => true, 'message' => '规则删除成功'];
}

function forward_normalize_domain($domain)
{
    return strtolower(rtrim(trim((string) $domain), '.'));
}

function forward_is_valid_domain($domain)
{
    $value = forward_normalize_domain($domain);
    if ($value === '' || strlen($value) > 253) {
        return false;
    }

    return preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/', $value) === 1;
}

function forward_get_remote_site_maps(array $settings, array $serverIds)
{
    return forward_get_remote_resource_maps(forward_collect_api_targets($settings, $serverIds), '/api/sites');
}

function forward_get_remote_site_snapshot(array $settings, array $serverIds)
{
    return forward_get_remote_resource_snapshot(forward_collect_api_targets($settings, $serverIds), '/api/sites');
}

function forward_remote_field(array $resource, $key, $default = '')
{
    return array_key_exists($key, $resource) ? $resource[$key] : $default;
}

function forward_remote_string(array $resource, $key, $default = '')
{
    return trim((string) forward_remote_field($resource, $key, $default));
}

function forward_remote_int(array $resource, $key, $default = 0)
{
    return (int) forward_remote_field($resource, $key, $default);
}

function forward_remote_enabled(array $resource)
{
    if (array_key_exists('enabled', $resource)) {
        return (bool) $resource['enabled'];
    }
    $status = strtolower(forward_remote_string($resource, 'status'));
    if ($status === 'stopped' || $status === 'inactive' || $status === 'disabled') {
        return false;
    }
    return true;
}

function forward_match_unique_service_for_remote_ip(array $services, $ip)
{
    $ip = forward_normalize_ip_literal($ip);
    if ($ip === '') {
        return null;
    }

    $matches = [];
    foreach ($services as $service) {
        $serviceId = (int) ($service['service_id'] ?? 0);
        if ($serviceId <= 0 || !in_array($ip, $service['ips'] ?? [], true)) {
            continue;
        }
        $matches[$serviceId] = $service;
    }

    return count($matches) === 1 ? reset($matches) : null;
}

function forward_unbound_remote_service(array $target, array $settings, $listenIp, $backendIp)
{
    $serverId = (int) ($target['server_id'] ?? 0);
    if ($serverId <= 0) {
        $inferred = forward_infer_server_id_from_listen_ip($settings, $listenIp);
        if ($inferred > 0) {
            $serverId = $inferred;
        }
    }

    $backendIp = forward_normalize_ip_literal($backendIp);
    return [
        'user_id' => 0,
        'product_name' => null,
        'server_id' => $serverId,
        'service_id' => 0,
        'ips' => $backendIp !== '' ? [$backendIp] : [],
    ];
}

function forward_services_by_api_target(array $services, array $settings)
{
    $targets = [];
    $servicesByTarget = [];
    foreach ($services as $service) {
        if (empty($service['ips'])) {
            continue;
        }
        $target = forward_get_api_target($settings, (int) ($service['server_id'] ?? 0));
        if (!forward_api_target_enabled($target)) {
            continue;
        }
        $key = $target['key'] ?? '';
        if ($key === '') {
            continue;
        }
        $targets[$key] = $target;
        if (!isset($servicesByTarget[$key])) {
            $servicesByTarget[$key] = [];
        }
        $servicesByTarget[$key][] = $service;
    }

    return [$targets, $servicesByTarget];
}

function forward_upsert_synced_rule(array $remoteRule, array $service)
{
    $remoteId = forward_remote_int($remoteRule, 'id');
    $outIp = forward_normalize_ip_literal(forward_remote_string($remoteRule, 'out_ip'));
    $inIp = forward_normalize_ip_literal(forward_remote_string($remoteRule, 'in_ip', '0.0.0.0'));
    $outSourceIp = forward_normalize_optional_ip(forward_remote_string($remoteRule, 'out_source_ip'));
    $protocol = forward_normalize_protocol(forward_remote_string($remoteRule, 'protocol', 'tcp'));
    if ($remoteId <= 0 || $outIp === '' || $protocol === '') {
        return false;
    }
    if ($inIp === '') {
        $inIp = '0.0.0.0';
    }
    if (!$outSourceIp['success']) {
        $outSourceIp = ['value' => ''];
    }

    $serverId = (int) ($service['server_id'] ?? 0);
    $existing = Capsule::table('mod_forward_rules')
        ->where('server_id', $serverId)
        ->where('remote_rule_id', $remoteId)
        ->first();

    if (!$existing) {
        $existing = Capsule::table('mod_forward_rules')
            ->where('server_id', $serverId)
            ->where('forward_rule_id', $remoteId)
            ->first();
    }

    $ruleName = forward_remote_string($remoteRule, 'remark');
    if ($ruleName === '') {
        $ruleName = 'Forward #' . $remoteId;
    }

    $values = [
        'forward_rule_id' => null,
        'remote_rule_id' => $remoteId,
        'user_id' => (int) ($service['user_id'] ?? 0),
        'product_name' => trim((string) ($service['product_name'] ?? '')) !== '' ? (string) $service['product_name'] : null,
        'server_id' => $serverId,
        'service_id' => (int) ($service['service_id'] ?? 0),
        'rule_name' => $ruleName,
        'in_interface' => forward_remote_string($remoteRule, 'in_interface'),
        'in_ip' => $inIp,
        'in_port' => forward_remote_int($remoteRule, 'in_port'),
        'out_interface' => forward_remote_string($remoteRule, 'out_interface'),
        'out_ip' => $outIp,
        'out_port' => forward_remote_int($remoteRule, 'out_port'),
        'out_source_ip' => $outSourceIp['value'],
        'protocol' => $protocol,
        'tag' => forward_remote_string($remoteRule, 'tag'),
        'transparent' => forward_remote_enabled(['enabled' => forward_remote_field($remoteRule, 'transparent', false)]) ? 1 : 0,
        'status' => forward_remote_enabled($remoteRule) ? 'active' : 'inactive',
        'updated_at' => date('Y-m-d H:i:s'),
    ];

    if ($existing) {
        $result = forward_execute_db_write('sync_remote_rule_update_error', function () use ($existing, $values) {
            return Capsule::table('mod_forward_rules')->where('id', (int) $existing->id)->update($values);
        });
        return !empty($result['success']);
    }

    $values['description'] = '';
    $values['created_at'] = date('Y-m-d H:i:s');
    $result = forward_execute_db_write('sync_remote_rule_insert_error', function () use ($values) {
        return Capsule::table('mod_forward_rules')->insert($values);
    });
    return !empty($result['success']);
}

function forward_upsert_synced_site(array $remoteSite, array $service)
{
    $remoteId = forward_remote_int($remoteSite, 'id');
    $backendIp = forward_normalize_ip_literal(forward_remote_string($remoteSite, 'backend_ip'));
    $listenIp = forward_normalize_ip_literal(forward_remote_string($remoteSite, 'listen_ip', '0.0.0.0'));
    $domain = forward_normalize_domain(forward_remote_string($remoteSite, 'domain'));
    $backendSourceIp = forward_normalize_optional_ip(forward_remote_string($remoteSite, 'backend_source_ip'));
    if ($remoteId <= 0 || $backendIp === '' || !forward_is_valid_domain($domain)) {
        return false;
    }
    if ($listenIp === '') {
        $listenIp = '0.0.0.0';
    }
    if (!$backendSourceIp['success']) {
        $backendSourceIp = ['value' => ''];
    }

    $serverId = (int) ($service['server_id'] ?? 0);
    $existing = Capsule::table('mod_forward_sites')
        ->where('server_id', $serverId)
        ->where('remote_site_id', $remoteId)
        ->first();

    if (!$existing) {
        $existing = Capsule::table('mod_forward_sites')
            ->where('server_id', $serverId)
            ->where('forward_site_id', $remoteId)
            ->first();
    }

    $values = [
        'forward_site_id' => null,
        'remote_site_id' => $remoteId,
        'user_id' => (int) ($service['user_id'] ?? 0),
        'product_name' => trim((string) ($service['product_name'] ?? '')) !== '' ? (string) $service['product_name'] : null,
        'server_id' => $serverId,
        'service_id' => (int) ($service['service_id'] ?? 0),
        'domain' => $domain,
        'listen_interface' => forward_remote_string($remoteSite, 'listen_interface'),
        'listen_ip' => $listenIp,
        'backend_ip' => $backendIp,
        'backend_source_ip' => $backendSourceIp['value'],
        'backend_http_port' => forward_remote_int($remoteSite, 'backend_http_port', 80),
        'backend_https_port' => forward_remote_int($remoteSite, 'backend_https_port', 443),
        'tag' => forward_remote_string($remoteSite, 'tag'),
        'transparent' => forward_remote_enabled(['enabled' => forward_remote_field($remoteSite, 'transparent', false)]) ? 1 : 0,
        'status' => forward_remote_enabled($remoteSite) ? 'active' : 'inactive',
        'updated_at' => date('Y-m-d H:i:s'),
    ];

    if ($existing) {
        $result = forward_execute_db_write('sync_remote_site_update_error', function () use ($existing, $values) {
            return Capsule::table('mod_forward_sites')->where('id', (int) $existing->id)->update($values);
        });
        return !empty($result['success']);
    }

    $values['description'] = '';
    $values['created_at'] = date('Y-m-d H:i:s');
    $result = forward_execute_db_write('sync_remote_site_insert_error', function () use ($values) {
        return Capsule::table('mod_forward_sites')->insert($values);
    });
    return !empty($result['success']);
}

function forward_sync_remote_bindings_for_services(array $services, array $settings, array $extraTargets = [], $includeUnmatched = false, $resources = null)
{
    if (empty($services)) {
        $targets = [];
        $servicesByTarget = [];
    } else {
        list($targets, $servicesByTarget) = forward_services_by_api_target($services, $settings);
    }

    foreach ($extraTargets as $key => $target) {
        if (!is_array($target) || !forward_api_target_enabled($target)) {
            continue;
        }
        $targetKey = trim((string) ($target['key'] ?? $key));
        if ($targetKey === '') {
            continue;
        }
        $targets[$targetKey] = $target;
        if (!isset($servicesByTarget[$targetKey])) {
            $servicesByTarget[$targetKey] = [];
        }
    }

    if (empty($targets)) {
        return ['rules' => 0, 'sites' => 0, 'errors' => 0];
    }

    $resources = is_array($resources) && !empty($resources) ? array_values(array_unique($resources)) : ['rules', 'sites'];
    $syncRules = in_array('rules', $resources, true);
    $syncSites = in_array('sites', $resources, true);
    $summary = ['rules' => 0, 'sites' => 0, 'errors' => 0];
    $ruleSnapshot = $syncRules ? forward_get_remote_resource_snapshot($targets, '/api/rules') : ['maps' => [], 'errors' => []];
    $siteSnapshot = $syncSites ? forward_get_remote_resource_snapshot($targets, '/api/sites') : ['maps' => [], 'errors' => []];

    foreach ($targets as $key => $target) {
        $targetServices = $servicesByTarget[$key] ?? [];
        if ($syncRules) {
            if (($ruleSnapshot['errors'][$key] ?? '') !== '') {
                $summary['errors']++;
                forward_log('sync_remote_rules_snapshot_error', [
                    'target' => forward_api_target_label($target),
                ], $ruleSnapshot['errors'][$key]);
            } else {
                foreach (($ruleSnapshot['maps'][$key] ?? []) as $remoteRule) {
                    $service = forward_match_unique_service_for_remote_ip($targetServices, forward_remote_string($remoteRule, 'out_ip'));
                    if ($service === null && $includeUnmatched) {
                        $service = forward_unbound_remote_service(
                            $target,
                            $settings,
                            forward_remote_string($remoteRule, 'in_ip', '0.0.0.0'),
                            forward_remote_string($remoteRule, 'out_ip')
                        );
                    }
                    if ($service === null) {
                        continue;
                    }
                    if (forward_upsert_synced_rule($remoteRule, $service)) {
                        $summary['rules']++;
                    }
                }
            }
        }

        if ($syncSites) {
            if (($siteSnapshot['errors'][$key] ?? '') !== '') {
                $summary['errors']++;
                forward_log('sync_remote_sites_snapshot_error', [
                    'target' => forward_api_target_label($target),
                ], $siteSnapshot['errors'][$key]);
            } else {
                foreach (($siteSnapshot['maps'][$key] ?? []) as $remoteSite) {
                    $service = forward_match_unique_service_for_remote_ip($targetServices, forward_remote_string($remoteSite, 'backend_ip'));
                    if ($service === null && $includeUnmatched) {
                        $service = forward_unbound_remote_service(
                            $target,
                            $settings,
                            forward_remote_string($remoteSite, 'listen_ip', '0.0.0.0'),
                            forward_remote_string($remoteSite, 'backend_ip')
                        );
                    }
                    if ($service === null) {
                        continue;
                    }
                    if (forward_upsert_synced_site($remoteSite, $service)) {
                        $summary['sites']++;
                    }
                }
            }
        }
    }

    return $summary;
}

function forward_sync_remote_bindings_for_service_id($serviceId, $settings = null)
{
    $settings = $settings === null ? forward_get_module_settings() : $settings;
    if (!is_array($settings)) {
        $settings = [];
    }
    $service = forward_get_service_by_id($serviceId, $settings, ['Active', 'Suspended', 'Terminated', 'Cancelled'], 'all');
    if ($service === null) {
        return ['rules' => 0, 'sites' => 0, 'errors' => 0];
    }
    return forward_sync_remote_bindings_for_services([$service], $settings);
}

function forward_find_service_in_list_by_id(array $services, $serviceId)
{
    $serviceId = (int) $serviceId;
    if ($serviceId <= 0) {
        return null;
    }

    foreach ($services as $service) {
        if ((int) ($service['service_id'] ?? 0) === $serviceId) {
            return $service;
        }
    }

    return null;
}

function forward_sync_client_service_bindings(array $services, array $settings, $serviceId)
{
    $service = forward_find_service_in_list_by_id($services, $serviceId);
    if ($service === null) {
        return ['success' => false, 'message' => '无权同步该服务或服务不存在'];
    }

    $result = forward_sync_remote_bindings_for_services([$service], $settings);
    if (!empty($result['errors'])) {
        return [
            'success' => false,
            'message' => '当前服务同步失败，请稍后重试或联系管理员查看 Forward 端点状态',
            'summary' => $result,
        ];
    }

    return [
        'success' => true,
        'message' => '当前服务规则已同步',
        'summary' => $result,
        'reload' => true,
    ];
}

function forward_sync_all_remote_bindings(array $settings)
{
    return forward_sync_remote_bindings_for_services(
        forward_get_all_forward_services($settings),
        $settings,
        forward_collect_configured_api_targets($settings),
        true
    );
}

function forward_get_local_sites($userId = null, $refreshRemote = true)
{
    $settings = forward_get_module_settings();
    $query = Capsule::table('mod_forward_sites')->orderBy('created_at', 'desc');
    if ($userId !== null) {
        $query->where('user_id', (int) $userId);
    }

    $rows = $query->get();
    $serverIds = [];
    foreach ($rows as $row) {
        $serverIds[] = forward_resolve_record_server_id($row, $settings, 'listen_ip');
    }
    $remoteSnapshot = $refreshRemote
        ? forward_get_remote_site_snapshot($settings, $serverIds)
        : ['maps' => [], 'errors' => []];
    $remoteMaps = $remoteSnapshot['maps'];
    $remoteErrors = $remoteSnapshot['errors'];
    $result = [];

    foreach ($rows as $row) {
        $resolvedServerId = forward_resolve_record_server_id($row, $settings, 'listen_ip');
        $target = forward_get_api_target($settings, $resolvedServerId);
        $remoteId = forward_get_site_remote_id($row);
        $remoteKey = $target['key'] ?? '';
        $remoteError = '';
        if (forward_api_target_enabled($target)) {
            $remoteError = (string) ($remoteErrors[$remoteKey] ?? '');
        } elseif ($remoteId > 0) {
            $remoteError = '当前宿主机未配置 Forward 端点';
        }
        $remote = null;
        if (
            $remoteId > 0
            && forward_api_target_enabled($target)
            && isset($remoteMaps[$remoteKey][$remoteId])
        ) {
            $remote = $remoteMaps[$remoteKey][$remoteId];
        }
        $statusMeta = forward_status_meta($remote, $row->status, $remoteError, $refreshRemote && $remoteId > 0);
        $result[] = [
            'id' => (int) $row->id,
            'forward_site_id' => $remoteId,
            'remote_site_id' => $remoteId,
            'user_id' => (int) $row->user_id,
            'product_name' => $row->product_name ?: '',
            'server_id' => $resolvedServerId,
            'service_id' => (int) ($row->service_id ?? 0),
            'server_label' => forward_get_server_label($resolvedServerId),
            'domain' => $row->domain,
            'listen_interface' => $row->listen_interface ?: '',
            'listen_ip' => $row->listen_ip,
            'listen_endpoint' => forward_format_endpoint_suffix($row->listen_ip, '80/443'),
            'backend_ip' => $row->backend_ip,
            'backend_source_ip' => $row->backend_source_ip ?: '',
            'backend_http_port' => (int) $row->backend_http_port,
            'backend_https_port' => (int) $row->backend_https_port,
            'tag' => $row->tag ?: '',
            'transparent' => (bool) $row->transparent,
            'status' => $row->status,
            'description' => $row->description ?: '',
            'created_at' => $row->created_at,
            'updated_at' => $row->updated_at,
            'remote_status' => $remote['status'] ?? '',
            'remote_error' => $remoteError,
            'enabled' => isset($remote['enabled']) ? (bool) $remote['enabled'] : ($row->status === 'active'),
            'status_text' => $statusMeta['text'],
            'status_class' => $statusMeta['class'],
        ];
    }

    return $result;
}

function forward_get_local_site_record($siteId)
{
    return Capsule::table('mod_forward_sites')->where('id', (int) $siteId)->first();
}

function forward_get_local_site($siteId, $userId = null)
{
    $query = Capsule::table('mod_forward_sites')->where('id', (int) $siteId);
    if ($userId !== null) {
        $query->where('user_id', (int) $userId);
    }
    $row = $query->first();
    if (!$row) {
        return null;
    }

    $settings = forward_get_module_settings();
    $resolvedServerId = forward_resolve_record_server_id($row, $settings, 'listen_ip');
    $target = forward_get_api_target($settings, $resolvedServerId);
    $remoteId = forward_get_site_remote_id($row);
    $remoteSnapshot = forward_get_remote_site_snapshot($settings, [$resolvedServerId]);
    $remoteMaps = $remoteSnapshot['maps'];
    $remoteErrors = $remoteSnapshot['errors'];
    $remoteKey = $target['key'] ?? '';
    $remoteError = '';
    if (forward_api_target_enabled($target)) {
        $remoteError = (string) ($remoteErrors[$remoteKey] ?? '');
    } elseif ($remoteId > 0) {
        $remoteError = '当前宿主机未配置 Forward 端点';
    }
    $remote = ($remoteId > 0 && forward_api_target_enabled($target) && isset($remoteMaps[$remoteKey][$remoteId]))
        ? $remoteMaps[$remoteKey][$remoteId]
        : null;
    $statusMeta = forward_status_meta($remote, $row->status, $remoteError, $remoteId > 0);

    return [
        'id' => (int) $row->id,
        'forward_site_id' => $remoteId,
        'remote_site_id' => $remoteId,
        'user_id' => (int) $row->user_id,
        'product_name' => $row->product_name ?: '',
        'server_id' => $resolvedServerId,
        'service_id' => (int) ($row->service_id ?? 0),
        'server_label' => forward_get_server_label($resolvedServerId),
        'domain' => $row->domain,
        'listen_interface' => $row->listen_interface ?: '',
        'listen_ip' => $row->listen_ip,
        'listen_endpoint' => forward_format_endpoint_suffix($row->listen_ip, '80/443'),
        'backend_ip' => $row->backend_ip,
        'backend_source_ip' => $row->backend_source_ip ?: '',
        'backend_http_port' => (int) $row->backend_http_port,
        'backend_https_port' => (int) $row->backend_https_port,
        'tag' => $row->tag ?: '',
        'transparent' => (bool) $row->transparent,
        'status' => $row->status,
        'description' => $row->description ?: '',
        'remote_error' => $remoteError,
        'status_text' => $statusMeta['text'],
        'status_class' => $statusMeta['class'],
    ];
}

function forward_has_remote_site_conflict($domain, $excludeRemoteSiteId = 0, $serverId = 0)
{
    $normalizedDomain = forward_normalize_domain($domain);
    $settings = forward_get_module_settings();
    $target = forward_get_api_target($settings, (int) $serverId);
    if (!forward_api_target_enabled($target)) {
        return false;
    }
    $remoteMaps = forward_get_remote_site_maps($settings, [(int) $serverId]);
    $remoteMap = $remoteMaps[$target['key']] ?? [];
    foreach ($remoteMap as $id => $site) {
        if ($excludeRemoteSiteId > 0 && (int) $id === (int) $excludeRemoteSiteId) {
            continue;
        }
        if (forward_normalize_domain($site['domain'] ?? '') === $normalizedDomain) {
            return true;
        }
    }
    return false;
}

function forward_validate_site_input(array $data, array $settings, $excludeLocalSiteId = 0, $excludeRemoteSiteId = 0, array $allowedListenIps = null, $targetServerId = 0, array $defaults = [])
{
    $defaults = array_merge([
        'listen_interface' => trim((string) ($settings['in_interface'] ?? '')),
        'tag' => trim((string) ($settings['default_tag'] ?? '')),
        'transparent' => forward_is_enabled_value($settings['transparent_mode'] ?? 'off'),
        'backend_source_ip' => '',
    ], $defaults);
    $listenIps = $allowedListenIps !== null ? array_values(array_unique($allowedListenIps)) : forward_get_all_server_ips($settings);
    if (empty($listenIps)) {
        return ['success' => false, 'message' => '当前服务未配置可用的入口 IP'];
    }
    $listenIp = forward_pick_listen_ip($data['listen_ip'] ?? '', $listenIps);
    if ($listenIp === '') {
        return ['success' => false, 'message' => '入口 IP 不在当前服务允许范围内'];
    }

    $domain = forward_normalize_domain($data['domain'] ?? '');
    if (!forward_is_valid_domain($domain)) {
        return ['success' => false, 'message' => '域名格式无效，请填写标准域名或 punycode'];
    }

    $backendIp = forward_normalize_ip_literal($data['backend_ip'] ?? $data['internal_ip'] ?? '');
    if ($backendIp === '') {
        return ['success' => false, 'message' => '目标 IP 必须是有效的 IP 地址'];
    }

    $backendHttpPort = (int) ($data['backend_http_port'] ?? 80);
    $backendHttpsPort = (int) ($data['backend_https_port'] ?? 443);

    if ($backendHttpPort < 0 || $backendHttpPort > 65535) {
        return ['success' => false, 'message' => 'HTTP 端口必须在 0-65535 之间'];
    }
    if ($backendHttpsPort < 0 || $backendHttpsPort > 65535) {
        return ['success' => false, 'message' => 'HTTPS 端口必须在 0-65535 之间'];
    }
    if ($backendHttpPort === 0 && $backendHttpsPort === 0) {
        return ['success' => false, 'message' => 'HTTP 和 HTTPS 端口至少启用一个'];
    }

    $transparent = forward_resolve_checkbox_value($data, 'transparent', !empty($defaults['transparent']));
    $normalizedSourceIP = forward_normalize_optional_ip($data['backend_source_ip'] ?? ($defaults['backend_source_ip'] ?? ''));
    if (!$normalizedSourceIP['success']) {
        return ['success' => false, 'message' => '回源 IP ' . $normalizedSourceIP['message']];
    }
    $backendSourceIP = $transparent ? '' : $normalizedSourceIP['value'];

    if ($transparent && !forward_ip_pair_is_pure_ipv4($listenIp, $backendIp)) {
        return ['success' => false, 'message' => '透传当前仅支持 IPv4 入口与目标 IP 组合'];
    }
    if ($backendSourceIP !== '' && forward_ip_family($backendSourceIP) !== forward_ip_family($backendIp)) {
        return ['success' => false, 'message' => '回源 IP 必须与目标 IP 地址族一致'];
    }

    $productName = trim((string) ($data['product_name'] ?? ''));
    if (forward_strlen($productName) > 100) {
        return ['success' => false, 'message' => '产品名称不能超过 100 个字符'];
    }

    $description = trim((string) ($data['description'] ?? ''));
    if (forward_strlen($description) > 2000) {
        return ['success' => false, 'message' => '描述不能超过 2000 个字符'];
    }

    $conflictQuery = Capsule::table('mod_forward_sites')
        ->where('server_id', (int) $targetServerId)
        ->where('domain', $domain);
    if ($excludeLocalSiteId > 0) {
        $conflictQuery->where('id', '!=', (int) $excludeLocalSiteId);
    }
    if ($conflictQuery->first()) {
        return ['success' => false, 'message' => '该域名已在模块中存在'];
    }

    if (forward_has_remote_site_conflict($domain, $excludeRemoteSiteId, $targetServerId)) {
        return ['success' => false, 'message' => '该域名已在 forward 中被其他站点占用'];
    }

    return [
        'success' => true,
        'data' => [
            'domain' => $domain,
            'listen_interface' => trim((string) ($data['listen_interface'] ?? $defaults['listen_interface'])),
            'listen_ip' => $listenIp,
            'listen_ips' => $listenIps,
            'backend_ip' => $backendIp,
            'backend_source_ip' => $backendSourceIP,
            'backend_http_port' => $backendHttpPort,
            'backend_https_port' => $backendHttpsPort,
            'tag' => trim((string) ($data['tag'] ?? $defaults['tag'])),
            'transparent' => $transparent,
            'description' => $description,
            'product_name' => $productName,
        ],
    ];
}

function forward_create_site(array $data, $userId = 0, $isClient = false)
{
    $settings = forward_get_module_settings();
    $clientPermissions = forward_client_permissions($settings);
    $service = null;
    $allowedListenIps = null;
    $targetServerId = 0;
    if ($isClient) {
        $allowedProducts = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
        $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
        $services = forward_get_user_services($userId, $allowedProducts, $allowedClientIps, ['Active'], forward_client_service_ip_family($settings));
        $service = forward_find_service_for_ip(
            $services,
            trim((string) ($data['backend_ip'] ?? $data['internal_ip'] ?? '')),
            (int) ($data['service_id'] ?? 0),
            (int) ($data['server_id'] ?? 0),
            (string) ($data['product_name'] ?? '')
        );
        if ($service === null) {
            return ['success' => false, 'message' => '目标 IP 不属于当前用户可用的服务'];
        }
        $allowedListenIps = forward_get_allowed_server_ips($settings, (int) ($service['server_id'] ?? 0));
        if (empty($allowedListenIps)) {
            return ['success' => false, 'message' => '该服务所属宿主机未配置入口 IP'];
        }
        $targetServerId = (int) ($service['server_id'] ?? 0);
        $data['listen_interface'] = trim((string) ($settings['in_interface'] ?? ''));
        $data['tag'] = trim((string) ($settings['default_tag'] ?? ''));
        $data['transparent'] = forward_is_enabled_value($settings['transparent_mode'] ?? 'off') ? '1' : '0';
        $data['backend_source_ip'] = '';
        if (empty($clientPermissions['site']['listen_ip'])) {
            $data['listen_ip'] = '';
        }
        if (empty($clientPermissions['site']['backend_ports'])) {
            $data['backend_http_port'] = 80;
            $data['backend_https_port'] = 443;
        }
        if (empty($clientPermissions['site']['description'])) {
            $data['description'] = '';
        }
    }

    if (!$isClient) {
        $serverResolution = forward_resolve_target_server_id(
            $settings,
            $data['listen_ip'] ?? '',
            (int) ($data['server_id'] ?? 0)
        );
        if (!$serverResolution['success']) {
            return $serverResolution;
        }
        $targetServerId = (int) ($serverResolution['server_id'] ?? 0);
    }

    $validated = forward_validate_site_input($data, $settings, 0, 0, $allowedListenIps, $targetServerId);
    if (!$validated['success']) {
        return $validated;
    }

    $site = $validated['data'];

    if ($isClient) {
        $sync = forward_sync_quota_group_before_create($services, $settings, $service, 'sites', '共享站点');
        if (empty($sync['success'])) {
            return $sync;
        }

        $quota = forward_product_site_quota($settings, $userId, $service);
        if (empty($quota['can_create'])) {
            $productLabel = trim((string) ($service['product_name'] ?? ''));
            $productText = $productLabel !== '' ? ('产品“' . $productLabel . '”') : '当前产品';
            return [
                'success' => false,
                'message' => $productText . '已达到共享站点数量限制（' . (int) $quota['count'] . '/' . (int) $quota['limit'] . '）',
            ];
        }

        $site['product_name'] = $service['product_name'];
    }

    $payload = forward_build_site_payload_from_site($site);
    $remoteCreate = forward_remote_create_resource('/api/sites', '/api/sites/toggle', $payload, $targetServerId, true);
    if (!$remoteCreate['success']) {
        return ['success' => false, 'message' => '后端创建站点失败：' . $remoteCreate['message']];
    }

    $remoteId = (int) ($remoteCreate['id'] ?? 0);
    $insert = forward_execute_db_write('create_site_local_insert_error', function () use ($site, $remoteId, $userId, $service, $targetServerId) {
        return Capsule::table('mod_forward_sites')->insert([
            'forward_site_id' => null,
            'remote_site_id' => $remoteId > 0 ? $remoteId : null,
            'user_id' => (int) $userId,
            'product_name' => $site['product_name'] ?: null,
            'server_id' => is_array($service) ? (int) ($service['server_id'] ?? 0) : $targetServerId,
            'service_id' => is_array($service) ? (int) ($service['service_id'] ?? 0) : 0,
            'domain' => $site['domain'],
            'listen_interface' => $site['listen_interface'],
            'listen_ip' => $site['listen_ip'],
            'backend_ip' => $site['backend_ip'],
            'backend_source_ip' => $site['backend_source_ip'],
            'backend_http_port' => $site['backend_http_port'],
            'backend_https_port' => $site['backend_https_port'],
            'tag' => $site['tag'],
            'transparent' => $site['transparent'] ? 1 : 0,
            'status' => 'active',
            'description' => $site['description'],
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s'),
        ]);
    });
    if (!$insert['success']) {
        $rolledBack = forward_best_effort_remote_delete_resource('/api/sites', $remoteId, $targetServerId);
        $message = '本地写入站点失败：' . $insert['message'];
        $message .= $rolledBack ? '；已回滚远端站点' : '；远端回滚失败，请手动删除已创建的远端站点';
        return ['success' => false, 'message' => $message];
    }

    return ['success' => true, 'message' => '共享站点创建成功'];
}

function forward_update_site(array $data, $userId = null)
{
    $siteId = (int) ($data['site_id'] ?? 0);
    if ($siteId <= 0) {
        return ['success' => false, 'message' => '无效的站点 ID'];
    }

    $record = Capsule::table('mod_forward_sites')->where('id', $siteId);
    if ($userId !== null) {
        $record->where('user_id', (int) $userId);
    }
    $existing = $record->first();
    if (!$existing) {
        return ['success' => false, 'message' => '站点不存在'];
    }

    if ($userId !== null) {
        $data['backend_ip'] = $existing->backend_ip;
    }

    $settings = forward_get_module_settings();
    $clientPermissions = forward_client_permissions($settings);
    if ($userId !== null) {
        $data['listen_interface'] = $existing->listen_interface ?: trim((string) ($settings['in_interface'] ?? ''));
        $data['tag'] = $existing->tag ?: trim((string) ($settings['default_tag'] ?? ''));
        $data['transparent'] = !empty($existing->transparent) ? '1' : '0';
        $data['backend_source_ip'] = $existing->backend_source_ip ?: '';
    }
    $existingServerId = forward_resolve_record_server_id($existing, $settings, 'listen_ip');
    $existingRemoteId = forward_get_site_remote_id($existing);
    $service = null;
    $allowedListenIps = null;
    $targetServerId = $existingServerId;
    if ($userId !== null) {
        $allowedProducts = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
        $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
        $services = forward_get_user_services($userId, $allowedProducts, $allowedClientIps, ['Active'], forward_client_service_ip_family($settings));
        $service = forward_find_service_for_ip(
            $services,
            trim((string) ($data['backend_ip'] ?? $data['internal_ip'] ?? '')),
            (int) ($existing->service_id ?? 0) > 0 ? (int) ($existing->service_id ?? 0) : (int) ($data['service_id'] ?? 0),
            $existingServerId > 0 ? $existingServerId : (int) ($data['server_id'] ?? 0),
            (string) ($existing->product_name ?? '')
        );
        if ($service === null) {
            return ['success' => false, 'message' => '目标 IP 不属于当前用户可用的服务'];
        }
        $allowedListenIps = forward_get_allowed_server_ips($settings, (int) ($service['server_id'] ?? 0));
        if (empty($allowedListenIps)) {
            return ['success' => false, 'message' => '该服务所属宿主机未配置入口 IP'];
        }
        $targetServerId = (int) ($service['server_id'] ?? 0);
        if (empty($clientPermissions['site']['listen_ip'])) {
            $data['listen_ip'] = forward_client_locked_listen_ip($existing->listen_ip ?? '', $allowedListenIps);
        }
        if (empty($clientPermissions['site']['backend_ports'])) {
            $data['backend_http_port'] = (int) ($existing->backend_http_port ?? 80);
            $data['backend_https_port'] = (int) ($existing->backend_https_port ?? 443);
        }
        if (empty($clientPermissions['site']['description'])) {
            $data['description'] = (string) ($existing->description ?? '');
        }
    } else {
        $serverResolution = forward_resolve_target_server_id(
            $settings,
            $data['listen_ip'] ?? $existing->listen_ip ?? '',
            (int) ($data['server_id'] ?? $existingServerId)
        );
        if (!$serverResolution['success']) {
            return $serverResolution;
        }
        $targetServerId = (int) ($serverResolution['server_id'] ?? 0);
    }
    $validated = forward_validate_site_input(
        $data,
        $settings,
        $siteId,
        ($existingRemoteId > 0 && $targetServerId === $existingServerId) ? $existingRemoteId : 0,
        $allowedListenIps,
        $targetServerId,
        [
            'listen_interface' => $existing->listen_interface ?: trim((string) ($settings['in_interface'] ?? '')),
            'tag' => $existing->tag ?: trim((string) ($settings['default_tag'] ?? '')),
            'transparent' => (bool) $existing->transparent,
            'backend_source_ip' => $existing->backend_source_ip ?: '',
        ]
    );
    if (!$validated['success']) {
        return $validated;
    }

    $site = $validated['data'];
    if ($userId !== null) {
        $site['product_name'] = $service['product_name'];
    }

    $sameRemote = $existingRemoteId > 0 && $targetServerId === $existingServerId;
    $desiredEnabled = $existing->status !== 'inactive';
    $updateValues = [
        'forward_site_id' => null,
        'remote_site_id' => null,
        'product_name' => $site['product_name'] ?: null,
        'server_id' => $userId !== null
            ? (is_array($service) ? (int) ($service['server_id'] ?? 0) : 0)
            : $targetServerId,
        'service_id' => $userId !== null
            ? (is_array($service) ? (int) ($service['service_id'] ?? 0) : 0)
            : (int) ($data['service_id'] ?? $existing->service_id ?? 0),
        'domain' => $site['domain'],
        'listen_interface' => $site['listen_interface'],
        'listen_ip' => $site['listen_ip'],
        'backend_ip' => $site['backend_ip'],
        'backend_source_ip' => $site['backend_source_ip'],
        'backend_http_port' => $site['backend_http_port'],
        'backend_https_port' => $site['backend_https_port'],
        'tag' => $site['tag'],
        'transparent' => $site['transparent'] ? 1 : 0,
        'description' => $site['description'],
        'updated_at' => date('Y-m-d H:i:s'),
    ];
    $restoreValues = [
        'forward_site_id' => forward_data_get($existing, 'forward_site_id') ?: null,
        'remote_site_id' => $existingRemoteId > 0 ? $existingRemoteId : null,
        'product_name' => $existing->product_name ?: null,
        'server_id' => (int) ($existing->server_id ?? 0),
        'service_id' => (int) ($existing->service_id ?? 0),
        'domain' => $existing->domain,
        'listen_interface' => $existing->listen_interface ?: '',
        'listen_ip' => $existing->listen_ip,
        'backend_ip' => $existing->backend_ip,
        'backend_source_ip' => $existing->backend_source_ip ?: '',
        'backend_http_port' => (int) $existing->backend_http_port,
        'backend_https_port' => (int) $existing->backend_https_port,
        'tag' => $existing->tag ?: '',
        'transparent' => !empty($existing->transparent) ? 1 : 0,
        'status' => $existing->status ?: 'active',
        'description' => $existing->description ?: '',
        'updated_at' => date('Y-m-d H:i:s'),
    ];

    if ($sameRemote) {
        $payload = forward_build_site_payload_from_site($site, $existingRemoteId);
        $api = forward_call_api('/api/sites', 'PUT', $payload, $targetServerId);
        if (!$api['success'] && !forward_is_api_not_found_message($api['message'] ?? '')) {
            return ['success' => false, 'message' => '后端更新站点失败：' . $api['message']];
        }
        if (!empty($api['success'])) {
            $updateValues['remote_site_id'] = $existingRemoteId > 0 ? $existingRemoteId : null;
            $dbUpdate = forward_execute_db_write('update_site_local_update_error', function () use ($siteId, $updateValues) {
                return Capsule::table('mod_forward_sites')->where('id', $siteId)->update($updateValues);
            });
            if (!$dbUpdate['success']) {
                $restoreApi = forward_call_api('/api/sites', 'PUT', forward_build_site_payload_from_record($existing), $existingServerId);
                $message = '本地更新站点失败：' . $dbUpdate['message'];
                $message .= !empty($restoreApi['success'])
                    ? '；已回滚远端站点'
                    : '；远端回滚失败：' . ($restoreApi['message'] ?? '未知错误');
                return ['success' => false, 'message' => $message];
            }

            return ['success' => true, 'message' => '共享站点更新成功'];
        }

        $sameRemote = false;
    }

    $newRemote = forward_remote_create_resource(
        '/api/sites',
        '/api/sites/toggle',
        forward_build_site_payload_from_site($site),
        $targetServerId,
        $desiredEnabled
    );
    if (!$newRemote['success']) {
        return ['success' => false, 'message' => '后端更新站点失败：' . $newRemote['message']];
    }

    $remoteId = (int) ($newRemote['id'] ?? 0);
    $updateValues['remote_site_id'] = $remoteId > 0 ? $remoteId : null;
    $dbUpdate = forward_execute_db_write('update_site_local_update_error', function () use ($siteId, $updateValues) {
        return Capsule::table('mod_forward_sites')->where('id', $siteId)->update($updateValues);
    });
    if (!$dbUpdate['success']) {
        $rolledBack = forward_best_effort_remote_delete_resource('/api/sites', $remoteId, $targetServerId);
        $message = '本地更新站点失败：' . $dbUpdate['message'];
        $message .= $rolledBack ? '；已回滚新建的远端站点' : '；新建的远端站点回滚失败，请手动清理';
        return ['success' => false, 'message' => $message];
    }

    if ($existingRemoteId > 0 && $targetServerId !== $existingServerId) {
        $cleanup = forward_remote_delete_resource('/api/sites', $existingRemoteId, $existingServerId);
        if (!$cleanup['success']) {
            $restoreLocal = forward_execute_db_write('update_site_local_restore_error', function () use ($siteId, $restoreValues) {
                return Capsule::table('mod_forward_sites')->where('id', $siteId)->update($restoreValues);
            });
            $rolledBackRemote = forward_best_effort_remote_delete_resource('/api/sites', $remoteId, $targetServerId);

            $message = '旧 Forward 端删除站点失败：' . $cleanup['message'];
            $message .= $restoreLocal['success'] ? '；已回滚本地配置' : '；本地回滚失败：' . $restoreLocal['message'];
            $message .= $rolledBackRemote ? '，并已清理新 Forward 端站点' : '，但新 Forward 端站点清理失败，请手动核对';
            return ['success' => false, 'message' => $message];
        }
    }

    return ['success' => true, 'message' => '共享站点更新成功'];
}

function forward_toggle_site($siteId, $userId = null)
{
    $query = Capsule::table('mod_forward_sites')->where('id', (int) $siteId);
    if ($userId !== null) {
        $query->where('user_id', (int) $userId);
    }
    $existing = $query->first();
    if (!$existing) {
        return ['success' => false, 'message' => '站点不存在'];
    }

    $settings = forward_get_module_settings();
    $serverId = forward_resolve_record_server_id($existing, $settings, 'listen_ip');
    $remoteId = forward_get_site_remote_id($existing);
    $enabled = $existing->status !== 'inactive';
    $currentEnabled = $enabled;
    if ($remoteId > 0) {
        $toggle = forward_remote_toggle_resource('/api/sites/toggle', $remoteId, $serverId, $currentEnabled);
        if (!$toggle['success']) {
            return ['success' => false, 'message' => '后端切换站点状态失败：' . $toggle['message']];
        }
        $enabled = $toggle['enabled'] === null ? !$currentEnabled : (bool) $toggle['enabled'];
    } else {
        $enabled = !$enabled;
    }

    $dbUpdate = forward_execute_db_write('toggle_site_local_update_error', function () use ($siteId, $enabled) {
        return Capsule::table('mod_forward_sites')
            ->where('id', (int) $siteId)
            ->update([
            'status' => $enabled ? 'active' : 'inactive',
            'updated_at' => date('Y-m-d H:i:s'),
            ]);
    });
    if (!$dbUpdate['success']) {
        if ($remoteId > 0) {
            $rollback = forward_remote_toggle_resource('/api/sites/toggle', $remoteId, $serverId, $enabled);
            $message = '本地切换站点状态失败：' . $dbUpdate['message'];
            $message .= $rollback['success'] ? '；已回滚远端状态' : '；远端状态回滚失败：' . $rollback['message'];
            return ['success' => false, 'message' => $message];
        }
        return ['success' => false, 'message' => '本地切换站点状态失败：' . $dbUpdate['message']];
    }

    return [
        'success' => true,
        'message' => $enabled ? '共享站点已启用' : '共享站点已禁用',
        'enabled' => $enabled,
    ];
}

function forward_delete_site($siteId, $userId = null)
{
    $query = Capsule::table('mod_forward_sites')->where('id', (int) $siteId);
    if ($userId !== null) {
        $query->where('user_id', (int) $userId);
    }
    $existing = $query->first();
    if (!$existing) {
        return ['success' => false, 'message' => '站点不存在'];
    }

    $settings = forward_get_module_settings();
    $serverId = forward_resolve_record_server_id($existing, $settings, 'listen_ip');
    $remoteId = forward_get_site_remote_id($existing);
    $remoteDelete = ['success' => true, 'state' => 'missing'];
    if ($remoteId > 0) {
        $remoteDelete = forward_remote_delete_resource('/api/sites', $remoteId, $serverId);
        if (!$remoteDelete['success']) {
            return ['success' => false, 'message' => '后端删除站点失败：' . $remoteDelete['message']];
        }
    }

    $dbDelete = forward_execute_db_write('delete_site_local_error', function () use ($siteId) {
        return Capsule::table('mod_forward_sites')->where('id', (int) $siteId)->delete();
    });
    if (!$dbDelete['success']) {
        $message = '本地删除站点失败：' . $dbDelete['message'];
        if (($remoteDelete['state'] ?? '') === 'deleted') {
            $recreate = forward_remote_create_resource(
                '/api/sites',
                '/api/sites/toggle',
                forward_build_site_payload_from_record($existing, 0),
                $serverId,
                $existing->status !== 'inactive'
            );
            if ($recreate['success']) {
                $newRemoteId = (int) ($recreate['id'] ?? 0);
                $repair = forward_execute_db_write('delete_site_local_rebind_error', function () use ($siteId, $newRemoteId) {
                    return Capsule::table('mod_forward_sites')
                        ->where('id', (int) $siteId)
                        ->update([
                            'forward_site_id' => null,
                            'remote_site_id' => $newRemoteId > 0 ? $newRemoteId : null,
                            'updated_at' => date('Y-m-d H:i:s'),
                        ]);
                });
                $message .= $repair['success']
                    ? '；已重建远端站点以保持一致'
                    : '；已重建远端站点，但本地回写新的远端 ID 失败：' . $repair['message'];
            } else {
                $message .= '；远端站点已删除，但重建失败：' . $recreate['message'];
            }
        }
        return ['success' => false, 'message' => $message];
    }

    return ['success' => true, 'message' => '共享站点删除成功'];
}

function forward_service_resource_query($table, $serviceId, $userId = 0)
{
    $query = Capsule::table($table)->where('service_id', (int) $serviceId);
    if ((int) $userId > 0) {
        $query->where('user_id', (int) $userId);
    }
    return $query;
}

function forward_toggle_remote_resource_to_state($togglePath, $remoteId, $serverId, $desiredEnabled, $currentEnabled)
{
    $remoteId = (int) $remoteId;
    if ($remoteId <= 0 || (bool) $desiredEnabled === (bool) $currentEnabled) {
        return ['success' => true, 'changed' => false, 'enabled' => (bool) $currentEnabled];
    }

    $toggle = forward_remote_toggle_resource($togglePath, $remoteId, $serverId, (bool) $currentEnabled);
    if (!$toggle['success']) {
        return ['success' => false, 'message' => $toggle['message'] ?? '远端切换失败'];
    }

    $enabled = $toggle['enabled'] === null ? (bool) $desiredEnabled : (bool) $toggle['enabled'];
    if ($enabled !== (bool) $desiredEnabled) {
        return ['success' => false, 'message' => '远端切换后状态与期望不一致'];
    }

    return ['success' => true, 'changed' => true, 'enabled' => $enabled];
}

function forward_set_service_resources_enabled($serviceId, $userId, $enabled, $restoreOnlySuspended = false)
{
    $serviceId = (int) $serviceId;
    $userId = (int) $userId;
    if ($serviceId <= 0) {
        return ['success' => false, 'message' => '无效的服务 ID'];
    }

    $settings = forward_get_module_settings();
    forward_sync_remote_bindings_for_service_id($serviceId, $settings);

    $summary = ['rules' => 0, 'sites' => 0, 'errors' => 0];
    $resources = [
        [
            'table' => 'mod_forward_rules',
            'remote_id' => 'remote_rule_id',
            'legacy_remote_id' => 'forward_rule_id',
            'toggle_path' => '/api/rules/toggle',
            'log_action' => 'service_lifecycle_rule_toggle_error',
        ],
        [
            'table' => 'mod_forward_sites',
            'remote_id' => 'remote_site_id',
            'legacy_remote_id' => 'forward_site_id',
            'toggle_path' => '/api/sites/toggle',
            'log_action' => 'service_lifecycle_site_toggle_error',
        ],
    ];

    foreach ($resources as $resource) {
        $query = forward_service_resource_query($resource['table'], $serviceId, $userId);
        if ($restoreOnlySuspended) {
            $query->where('service_suspended', 1);
        }
        $rows = $query->get();
        foreach ($rows as $row) {
            $remoteId = (int) (forward_data_get($row, $resource['remote_id'], 0) ?: forward_data_get($row, $resource['legacy_remote_id'], 0));
            $serverId = (int) forward_data_get($row, 'server_id', 0);
            $currentEnabled = (forward_data_get($row, 'status', 'active') !== 'inactive');
            $shouldMarkSuspended = !$enabled && $currentEnabled;
            $toggle = ['success' => true, 'changed' => false, 'enabled' => $currentEnabled];
            if ($remoteId > 0) {
                $toggle = forward_toggle_remote_resource_to_state(
                    $resource['toggle_path'],
                    $remoteId,
                    $serverId,
                    (bool) $enabled,
                    $currentEnabled
                );
            }
            if (!$toggle['success']) {
                $summary['errors']++;
                forward_log($resource['log_action'], [
                    'service_id' => $serviceId,
                    'user_id' => $userId,
                    'remote_id' => $remoteId,
                    'server_id' => $serverId,
                    'desired_enabled' => (bool) $enabled,
                ], $toggle['message'] ?? '远端切换失败');
                continue;
            }

            $updateValues = [
                'status' => $enabled ? 'active' : 'inactive',
                'updated_at' => date('Y-m-d H:i:s'),
            ];
            if (!$enabled && $shouldMarkSuspended) {
                $updateValues['service_suspended'] = 1;
            } elseif ($enabled && $restoreOnlySuspended) {
                $updateValues['service_suspended'] = 0;
            }

            $result = forward_execute_db_write('service_lifecycle_local_status_update_error', function () use ($resource, $row, $updateValues) {
                return Capsule::table($resource['table'])->where('id', (int) $row->id)->update($updateValues);
            });
            if (!$result['success']) {
                $summary['errors']++;
                continue;
            }

            if ($resource['table'] === 'mod_forward_rules') {
                $summary['rules']++;
            } else {
                $summary['sites']++;
            }
        }
    }

    return ['success' => $summary['errors'] === 0, 'summary' => $summary];
}

function forward_delete_service_resources($serviceId, $userId = 0)
{
    $serviceId = (int) $serviceId;
    $userId = (int) $userId;
    if ($serviceId <= 0) {
        return ['success' => false, 'message' => '无效的服务 ID'];
    }

    $settings = forward_get_module_settings();
    forward_sync_remote_bindings_for_service_id($serviceId, $settings);

    $summary = ['rules' => 0, 'sites' => 0, 'errors' => 0];
    $resources = [
        [
            'table' => 'mod_forward_rules',
            'remote_id' => 'remote_rule_id',
            'legacy_remote_id' => 'forward_rule_id',
            'delete_path' => '/api/rules',
            'log_action' => 'service_lifecycle_rule_delete_error',
        ],
        [
            'table' => 'mod_forward_sites',
            'remote_id' => 'remote_site_id',
            'legacy_remote_id' => 'forward_site_id',
            'delete_path' => '/api/sites',
            'log_action' => 'service_lifecycle_site_delete_error',
        ],
    ];

    foreach ($resources as $resource) {
        $rows = forward_service_resource_query($resource['table'], $serviceId, $userId)->get();
        foreach ($rows as $row) {
            $remoteId = (int) (forward_data_get($row, $resource['remote_id'], 0) ?: forward_data_get($row, $resource['legacy_remote_id'], 0));
            $serverId = (int) forward_data_get($row, 'server_id', 0);
            if ($remoteId > 0) {
                $remoteDelete = forward_remote_delete_resource($resource['delete_path'], $remoteId, $serverId);
                if (!$remoteDelete['success']) {
                    $summary['errors']++;
                    forward_log($resource['log_action'], [
                        'service_id' => $serviceId,
                        'user_id' => $userId,
                        'remote_id' => $remoteId,
                        'server_id' => $serverId,
                    ], $remoteDelete['message'] ?? '远端删除失败');
                    continue;
                }
            }

            $result = forward_execute_db_write('service_lifecycle_local_delete_error', function () use ($resource, $row) {
                return Capsule::table($resource['table'])->where('id', (int) $row->id)->delete();
            });
            if (!$result['success']) {
                $summary['errors']++;
                continue;
            }

            if ($resource['table'] === 'mod_forward_rules') {
                $summary['rules']++;
            } else {
                $summary['sites']++;
            }
        }
    }

    return ['success' => $summary['errors'] === 0, 'summary' => $summary];
}

function forward_service_context_from_hook_vars(array $vars)
{
    $params = is_array($vars['params'] ?? null) ? $vars['params'] : [];
    $serviceId = (int) ($params['serviceid'] ?? $vars['serviceid'] ?? 0);
    $userId = (int) ($params['userid'] ?? $vars['userid'] ?? $vars['clientId'] ?? 0);

    return ['service_id' => $serviceId, 'user_id' => $userId];
}

function forward_handle_service_lifecycle_hook(array $vars, $action)
{
    try {
        forward_ensure_runtime_schema();
        $context = forward_service_context_from_hook_vars($vars);
        $serviceId = (int) $context['service_id'];
        $userId = (int) $context['user_id'];
        if ($serviceId <= 0) {
            forward_log('service_lifecycle_missing_service_id', ['action' => $action], $vars);
            return;
        }

        if ($action === 'suspend') {
            $result = forward_set_service_resources_enabled($serviceId, $userId, false, false);
        } elseif ($action === 'unsuspend') {
            $result = forward_set_service_resources_enabled($serviceId, $userId, true, true);
        } else {
            $result = forward_delete_service_resources($serviceId, $userId);
        }

        forward_log('service_lifecycle_' . $action, [
            'service_id' => $serviceId,
            'user_id' => $userId,
        ], $result);
    } catch (Throwable $e) {
        forward_log('service_lifecycle_hook_error', [
            'action' => $action,
            'file' => $e->getFile(),
            'line' => $e->getLine(),
        ], $e->getMessage(), $e->getTraceAsString());
    }
}

function forward_json_response(array $payload)
{
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function forward_handle_admin_ajax()
{
    forward_ensure_runtime_schema();

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['action'])) {
        return;
    }

    if (!forward_validate_csrf_token($_POST['csrf_token'] ?? '')) {
        forward_json_response(['success' => false, 'message' => 'CSRF 校验失败']);
    }

    switch ($_POST['action']) {
        case 'add_rule':
            forward_json_response(forward_create_rule($_POST, 0, false));
            break;
        case 'edit_rule':
            forward_json_response(forward_update_rule($_POST, null));
            break;
        case 'toggle_rule':
            forward_json_response(forward_toggle_rule((int) ($_POST['rule_id'] ?? 0), null));
            break;
        case 'delete_rule':
            forward_json_response(forward_delete_rule((int) ($_POST['rule_id'] ?? 0), null));
            break;
        case 'add_site':
            forward_json_response(forward_create_site($_POST, 0, false));
            break;
        case 'edit_site':
            forward_json_response(forward_update_site($_POST, null));
            break;
        case 'toggle_site':
            forward_json_response(forward_toggle_site((int) ($_POST['site_id'] ?? 0), null));
            break;
        case 'delete_site':
            forward_json_response(forward_delete_site((int) ($_POST['site_id'] ?? 0), null));
            break;
        default:
            forward_json_response(['success' => false, 'message' => '不支持的操作']);
            break;
    }
}

function forward_handle_client_ajax()
{
    forward_ensure_runtime_schema();

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['action'])) {
        return;
    }

    $clientId = isset($_SESSION['uid']) ? (int) $_SESSION['uid'] : 0;
    if ($clientId <= 0) {
        forward_json_response(['success' => false, 'message' => '请先登录']);
    }

    $settings = forward_get_module_settings();
    $enabled = forward_is_enabled_value($settings['enable_client_area'] ?? 'yes');
    if (!$enabled) {
        forward_json_response(['success' => false, 'message' => 'Forward 功能当前未开放。']);
    }

    $allowedProducts = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
    $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
    $services = forward_get_user_services($clientId, $allowedProducts, $allowedClientIps, ['Active'], forward_client_service_ip_family($settings));
    if (empty($services)) {
        forward_json_response(['success' => false, 'message' => '您的产品当前未开放 Forward 规则管理。']);
    }

    if (!forward_validate_csrf_token($_POST['csrf_token'] ?? '')) {
        forward_json_response(['success' => false, 'message' => 'CSRF 校验失败']);
    }

    switch ($_POST['action']) {
        case 'add_rule':
            forward_json_response(forward_create_rule($_POST, $clientId, true));
            break;
        case 'edit_rule':
            forward_json_response(forward_update_rule($_POST, $clientId));
            break;
        case 'toggle_rule':
            forward_json_response(forward_toggle_rule((int) ($_POST['rule_id'] ?? 0), $clientId));
            break;
        case 'delete_rule':
            forward_json_response(forward_delete_rule((int) ($_POST['rule_id'] ?? 0), $clientId));
            break;
        case 'add_site':
            forward_json_response(forward_create_site($_POST, $clientId, true));
            break;
        case 'edit_site':
            forward_json_response(forward_update_site($_POST, $clientId));
            break;
        case 'toggle_site':
            forward_json_response(forward_toggle_site((int) ($_POST['site_id'] ?? 0), $clientId));
            break;
        case 'delete_site':
            forward_json_response(forward_delete_site((int) ($_POST['site_id'] ?? 0), $clientId));
            break;
        case 'sync_service':
            forward_json_response(forward_sync_client_service_bindings($services, $settings, (int) ($_POST['service_id'] ?? 0)));
            break;
        default:
            forward_json_response(['success' => false, 'message' => '不支持的操作']);
            break;
    }
}

function forward_protocol_select_html(array $protocols)
{
    $html = '';
    foreach ($protocols as $protocol) {
        $html .= '<option value="' . htmlspecialchars($protocol, ENT_QUOTES, 'UTF-8') . '">' .
            htmlspecialchars(strtoupper($protocol), ENT_QUOTES, 'UTF-8') .
            '</option>';
    }
    return $html;
}

function forward_output($vars)
{
    try {
        forward_output_render($vars);
    } catch (Throwable $e) {
        $context = [
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'action' => $_POST['action'] ?? '',
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'file' => $e->getFile(),
            'line' => $e->getLine(),
        ];
        forward_log('admin_output_error', $context, $e->getMessage(), $e->getTraceAsString());

        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && !empty($_POST['action'])) {
            forward_json_response(['success' => false, 'message' => 'Forward 后台操作失败：' . $e->getMessage()]);
        }

        forward_render_admin_error('Forward 后台加载失败', $e, $context);
    }
}

function forward_render_admin_error($title, Throwable $e, array $context = [])
{
    $title = htmlspecialchars((string) $title, ENT_QUOTES, 'UTF-8');
    $message = htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    $file = htmlspecialchars((string) $e->getFile(), ENT_QUOTES, 'UTF-8');
    $line = (int) $e->getLine();
    $contextJson = htmlspecialchars(json_encode(forward_sanitize_log_value($context), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), ENT_QUOTES, 'UTF-8');

    echo '<div class="forward-admin-error" style="margin:20px 0;padding:18px 20px;border:1px solid #f0b8b8;border-radius:14px;background:#fff7f7;color:#6f1d1d;">';
    echo '<h3 style="margin:0 0 10px;font-size:18px;">' . $title . '</h3>';
    echo '<p style="margin:0 0 10px;">模块后台初始化失败，已写入 WHMCS Activity Log / Module Log / PHP error_log 兜底日志。</p>';
    echo '<p style="margin:0 0 10px;"><strong>错误：</strong>' . $message . '</p>';
    echo '<p style="margin:0 0 10px;"><strong>位置：</strong><code>' . $file . ':' . $line . '</code></p>';
    if ($contextJson !== '' && $contextJson !== 'null') {
        echo '<details style="margin-top:10px;"><summary style="cursor:pointer;">上下文</summary><pre style="white-space:pre-wrap;margin-top:8px;">' . $contextJson . '</pre></details>';
    }
    echo '</div>';
}

function forward_output_render($vars)
{
    forward_ensure_runtime_schema();

    forward_handle_admin_ajax();

    $settings = forward_get_module_settings();
    forward_sync_all_remote_bindings($settings);
    $rules = forward_get_local_rules();
    $sites = forward_get_local_sites();
    $activeRuleCount = 0;
    $activeSiteCount = 0;
    $managedUserCount = [];
    foreach ($rules as $rule) {
        if (!empty($rule['enabled'])) {
            $activeRuleCount++;
        }
        if (!empty($rule['user_id'])) {
            $managedUserCount[(int) $rule['user_id']] = true;
        }
    }
    foreach ($sites as $site) {
        if (!empty($site['enabled'])) {
            $activeSiteCount++;
        }
        if (!empty($site['user_id'])) {
            $managedUserCount[(int) $site['user_id']] = true;
        }
    }
    $inactiveRuleCount = count($rules) - $activeRuleCount;
    $inactiveSiteCount = count($sites) - $activeSiteCount;
    $protocolSelect = forward_protocol_select_html(forward_protocol_options($settings['allowed_protocols'] ?? 'tcp+udp'));
    $allServerIps = forward_get_all_server_ips($settings);
    $adminListenPortRange = forward_get_listen_port_range($settings, false);
    $adminServerOptions = forward_get_admin_server_options($settings);
    $adminViewServerOptions = $adminServerOptions;
    foreach (array_merge($rules, $sites) as $record) {
        $recordServerId = (int) ($record['server_id'] ?? 0);
        $key = (string) $recordServerId;
        if (!isset($adminViewServerOptions[$key])) {
            $adminViewServerOptions[$key] = [
                'server_id' => $recordServerId,
                'server_label' => $record['server_label'] ?? forward_get_server_label($recordServerId),
                'listen_ips' => [],
                'listen_ips_csv' => '',
                'target_label' => '',
            ];
        }
    }
    uksort($adminViewServerOptions, function ($a, $b) {
        return (int) $a <=> (int) $b;
    });
    $serverIp = htmlspecialchars(forward_format_ip_list($allServerIps), ENT_QUOTES, 'UTF-8');
    $adminServerOptionsHtml = forward_admin_server_select_html($adminServerOptions);
    $adminServerFilterHtml = forward_admin_server_filter_html($adminViewServerOptions);
    $adminServerOptionsJs = json_encode($adminServerOptions, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($adminServerOptionsJs === false) {
        $adminServerOptionsJs = '{}';
    }
    $apiEndpoint = htmlspecialchars(forward_format_api_target_summary($settings), ENT_QUOTES, 'UTF-8');
    $defaultTag = htmlspecialchars((string) ($settings['default_tag'] ?? ''), ENT_QUOTES, 'UTF-8');
    $inInterface = htmlspecialchars((string) ($settings['in_interface'] ?? ''), ENT_QUOTES, 'UTF-8');
    $outInterface = htmlspecialchars((string) ($settings['out_interface'] ?? ''), ENT_QUOTES, 'UTF-8');
    $adminListenPortRangeText = htmlspecialchars((string) $adminListenPortRange['text'], ENT_QUOTES, 'UTF-8');
    $csrfToken = htmlspecialchars(forward_get_csrf_token(), ENT_QUOTES, 'UTF-8');
    $csrfTokenJs = json_encode(forward_get_csrf_token(), JSON_UNESCAPED_UNICODE);
    $adminDefaultTransparentJs = json_encode(forward_is_enabled_value($settings['transparent_mode'] ?? 'off'));
    $legacyServerMapNotice = forward_has_legacy_server_ip_product_map($settings)
        ? '检测到旧版按产品映射入口 IP 配置，它已不再参与宿主机匹配。请将 server_ip_product_map 手动迁移到新的 server_ip_server_map。'
        : '';

    echo <<<HTML
<style>
.forward-admin {
  --forward-ink: #102a32;
  --forward-muted: #3f5962;
  --forward-line: #b8c9d0;
  --forward-soft: #eef5f6;
  --forward-hero-a: #102a32;
  --forward-hero-b: #245f62;
  --forward-accent: #efb366;
  --forward-card-shadow: 0 20px 46px rgba(16, 42, 50, 0.14);
  width: 100%;
  max-width: 100%;
  color: var(--forward-ink);
}
.forward-admin *,
.forward-admin *::before,
.forward-admin *::after {
  box-sizing: border-box;
}
.forward-admin .panel {
  border: 1px solid var(--forward-line);
  border-radius: 18px;
  box-shadow: var(--forward-card-shadow);
  overflow: hidden;
}
.forward-admin .panel-heading {
  background: linear-gradient(135deg, var(--forward-hero-a), var(--forward-hero-b));
  color: #fff;
  border: 0;
  padding: 18px 22px;
}
.forward-admin .panel-body {
  padding: 22px;
  background: #fff;
}
.forward-admin__hero {
  display: grid;
  grid-template-columns: minmax(0, 1.5fr) minmax(280px, 1fr);
  gap: 16px;
  margin-bottom: 18px;
}
.forward-admin__intro {
  min-width: 0;
  background: linear-gradient(135deg, rgba(23, 49, 58, 0.98), rgba(45, 93, 99, 0.92));
  border-radius: 22px;
  color: #fff;
  padding: 24px 26px;
  box-shadow: var(--forward-card-shadow);
}
.forward-admin__eyebrow {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 999px;
  background: rgba(239, 179, 102, 0.16);
  color: #ffd6a0;
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.forward-admin__intro h2 {
  margin: 10px 0 8px;
  font-size: 28px;
  font-weight: 700;
}
.forward-admin__intro p {
  margin: 0;
  max-width: 640px;
  color: rgba(255, 255, 255, 0.82);
}
.forward-admin__meta {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
.forward-admin__stat {
  min-width: 0;
  background: #fff;
  border: 1px solid var(--forward-line);
  border-radius: 18px;
  padding: 18px;
  box-shadow: var(--forward-card-shadow);
  transition: border-color 160ms ease, box-shadow 160ms ease;
}
.forward-admin__stat:hover {
  border-color: #8eb0ba;
  box-shadow: 0 24px 54px rgba(16, 42, 50, 0.16);
}
.forward-admin__notice {
  position: sticky;
  top: 12px;
  z-index: 50;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 18px;
  padding: 14px 16px;
  border-radius: 14px;
  border: 1px solid transparent;
  font-weight: 600;
  box-shadow: 0 18px 38px rgba(16, 42, 50, 0.14);
}
.forward-admin__notice--success {
  background: #e8f6f1;
  border-color: #98d2c1;
  color: #075c49;
}
.forward-admin__notice--warning {
  background: #fff3df;
  border-color: #e8b36f;
  color: #7a410c;
}
.forward-admin__notice--danger {
  background: #fff0ef;
  border-color: #e59a95;
  color: #8d221e;
}
.forward-admin__notice-text {
  min-width: 0;
  overflow-wrap: anywhere;
}
.forward-admin__notice-action {
  flex: 0 0 auto;
  border: 0;
  border-radius: 999px;
  padding: 7px 12px;
  background: #102a32;
  color: #fff;
  font-weight: 700;
  transition: transform 160ms ease, background 160ms ease, box-shadow 160ms ease;
}
.forward-admin__notice-action:hover,
.forward-admin__notice-action:focus {
  background: #245f62;
  box-shadow: 0 8px 18px rgba(16, 42, 50, 0.22);
  color: #fff;
  transform: translateY(-1px);
}
.forward-admin__stat-label {
  display: block;
  font-size: 12px;
  color: var(--forward-muted);
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.forward-admin__stat-value {
  display: block;
  margin-top: 8px;
  font-size: 26px;
  font-weight: 700;
  color: var(--forward-ink);
}
.forward-admin__stat-note {
  display: block;
  margin-top: 6px;
  color: var(--forward-muted);
  font-size: 13px;
}
.forward-admin__summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
  margin-bottom: 18px;
}
.forward-admin__summary-card {
  min-width: 0;
  border: 1px solid var(--forward-line);
  border-radius: 16px;
  background: #fff;
  padding: 16px 18px;
}
.forward-admin__summary-card strong,
.forward-admin__summary-card code {
  display: block;
  margin-top: 8px;
}
.forward-admin__toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  margin-bottom: 18px;
  padding: 14px 16px;
  border: 1px solid var(--forward-line);
  border-radius: 16px;
  background: #f7fbfc;
}
.forward-admin__toolbar-label {
  display: block;
  margin: 0 0 4px;
  color: var(--forward-muted);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.forward-admin__toolbar-text {
  margin: 0;
  color: var(--forward-muted);
  font-size: 13px;
}
.forward-admin__toolbar-control {
  min-width: 260px;
}
.forward-admin code {
  max-width: 100%;
  border-radius: 10px;
  padding: 2px 8px;
  background: var(--forward-soft);
  color: var(--forward-ink);
  overflow-wrap: anywhere;
  white-space: normal;
}
.forward-admin .table-responsive {
  border: 1px solid var(--forward-line);
  border-radius: 16px;
  overflow-x: auto;
  overflow-y: hidden;
  -webkit-overflow-scrolling: touch;
}
.forward-admin .table {
  min-width: 860px;
  margin: 0;
}
.forward-admin .table > thead > tr > th {
  border-top: 0;
  border-bottom: 1px solid var(--forward-line);
  background: #e8f0f2;
  color: #284650;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.forward-admin .table > tbody > tr > td {
  vertical-align: middle;
  border-top: 1px solid #dce7eb;
}
.forward-admin .table > tbody > tr:hover {
  background: #f6fafb;
}
.forward-admin .table > tbody > tr.is-removing {
  opacity: 0.45;
  transform: translateX(6px);
  transition: opacity 180ms ease, transform 180ms ease;
}
.forward-admin .btn {
  border-radius: 999px;
  font-weight: 600;
  transition: transform 150ms ease, box-shadow 150ms ease, background 150ms ease, border-color 150ms ease, color 150ms ease, opacity 150ms ease;
}
.forward-admin .btn:hover,
.forward-admin .btn:focus {
  transform: translateY(-1px);
  box-shadow: 0 8px 18px rgba(16, 42, 50, 0.14);
}
.forward-admin .btn:active {
  transform: translateY(0);
  box-shadow: none;
}
.forward-admin .btn.is-loading {
  cursor: progress;
  opacity: 0.78;
}
.forward-admin .btn-primary {
  color: #fff;
  background: linear-gradient(135deg, #164b54, #2c747b);
  border-color: transparent;
}
.forward-admin .btn-warning {
  color: #102a32;
  background: #f0b35e;
  border-color: #d89943;
}
.forward-admin .btn-danger {
  color: #fff;
  background: #b63a34;
  border-color: #9e302b;
}
.forward-admin .label {
  display: inline-block;
  padding: 5px 10px;
  border-radius: 999px;
}
.forward-admin .label-success {
  background: #0f7b62;
}
.forward-admin .label-default {
  background: #536b74;
}
.forward-admin .label-info {
  background: #185f78;
}
.forward-admin .label-warning {
  background: #985719;
}
.forward-admin .label-danger {
  background: #a5332e;
}
.forward-admin .modal-content {
  border-radius: 20px;
  overflow: hidden;
}
.forward-admin .modal-header {
  background: linear-gradient(135deg, var(--forward-hero-a), var(--forward-hero-b));
  color: #fff;
}
@media (max-width: 991px) {
  .forward-admin__hero,
  .forward-admin__summary {
    grid-template-columns: 1fr;
  }
  .forward-admin__meta {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 767px) {
  .forward-admin .panel-body {
    padding: 16px;
  }
  .forward-admin__meta {
    grid-template-columns: 1fr;
  }
  .forward-admin__toolbar {
    align-items: stretch;
    flex-direction: column;
  }
  .forward-admin__toolbar-control {
    min-width: 0;
    width: 100%;
  }
}
</style>
HTML;

    echo '<div class="forward-addon">';
    echo '<div class="forward-admin">';
    echo '<div class="forward-admin__hero">';
    echo '<div class="forward-admin__intro"><span class="forward-admin__eyebrow">Forward</span><h2>规则管理面板</h2><p>管理 forward 的入口规则，支持后台创建、编辑、启停和删除，并同步客户区可见数据。</p></div>';
    echo '<div class="forward-admin__meta">';
    echo '<div class="forward-admin__stat"><span class="forward-admin__stat-label">规则总数</span><span class="forward-admin__stat-value">' . count($rules) . '</span><span class="forward-admin__stat-note">本地已记录的 forward 端口规则</span></div>';
    echo '<div class="forward-admin__stat"><span class="forward-admin__stat-label">共享站点总数</span><span class="forward-admin__stat-value">' . count($sites) . '</span><span class="forward-admin__stat-note">80/443 共享建站配置</span></div>';
    echo '<div class="forward-admin__stat"><span class="forward-admin__stat-label">启用中</span><span class="forward-admin__stat-value">' . ($activeRuleCount + $activeSiteCount) . '</span><span class="forward-admin__stat-note">规则 ' . $activeRuleCount . ' / 站点 ' . $activeSiteCount . '</span></div>';
    echo '<div class="forward-admin__stat"><span class="forward-admin__stat-label">已停用</span><span class="forward-admin__stat-value">' . ($inactiveRuleCount + $inactiveSiteCount) . '</span><span class="forward-admin__stat-note">规则 ' . $inactiveRuleCount . ' / 站点 ' . $inactiveSiteCount . '</span></div>';
    echo '<div class="forward-admin__stat"><span class="forward-admin__stat-label">客户数</span><span class="forward-admin__stat-value">' . count($managedUserCount) . '</span><span class="forward-admin__stat-note">拥有规则的客户账号</span></div>';
    echo '</div>';
    echo '</div>';
    echo '<div class="forward-admin__summary">';
    echo '<div class="forward-admin__summary-card"><span>入口 IP 池</span><code>' . $serverIp . '</code></div>';
    echo '<div class="forward-admin__summary-card"><span>Forward 端点</span><strong>' . ($apiEndpoint !== '' ? $apiEndpoint : '-') . '</strong></div>';
    echo '<div class="forward-admin__summary-card"><span>默认标签</span><strong>' . ($defaultTag !== '' ? $defaultTag : '-') . '</strong></div>';
    echo '<div class="forward-admin__summary-card"><span>接口绑定</span><strong>入 ' . ($inInterface !== '' ? $inInterface : '-') . ' / 出 ' . ($outInterface !== '' ? $outInterface : '-') . '</strong></div>';
    echo '</div>';
    echo '<div class="forward-admin__toolbar">';
    echo '<div><span class="forward-admin__toolbar-label">当前视图</span><p class="forward-admin__toolbar-text" id="forwardAdminServerFilterMeta">按宿主机切换规则和共享站点列表。</p></div>';
    echo '<select class="form-control forward-admin__toolbar-control" id="forwardAdminServerFilter">' . $adminServerFilterHtml . '</select>';
    echo '</div>';
    if ($legacyServerMapNotice !== '') {
        echo '<div class="alert alert-warning" style="border-radius:14px;margin-bottom:18px;">' . htmlspecialchars($legacyServerMapNotice, ENT_QUOTES, 'UTF-8') . '</div>';
    }
    echo '<div id="forwardAdminNotice" class="forward-admin__notice" style="display:none;"></div>';

    echo '<div class="panel panel-default">';
    echo '<div class="panel-heading"><div class="row">';
    echo '<div class="col-sm-6"><strong>规则列表</strong></div>';
    echo '<div class="col-sm-6 text-right"><button type="button" class="btn btn-primary" id="forwardAddRuleBtn">+ 添加规则</button></div>';
    echo '</div></div><div class="panel-body">';
    echo '<div class="table-responsive"><table class="table table-striped table-bordered">';
    echo '<thead><tr><th>ID</th><th>规则名称</th><th>入口地址</th><th>目标地址</th><th>协议</th><th>标签</th><th>状态</th><th>用户</th><th>操作</th></tr></thead><tbody>';

    if (!empty($rules)) {
        foreach ($rules as $rule) {
            $ruleJson = htmlspecialchars(json_encode($rule, JSON_UNESCAPED_UNICODE), ENT_QUOTES, 'UTF-8');
            $ruleSourceMeta = !empty($rule['transparent'])
                ? '源地址：透传'
                : (!empty($rule['out_source_ip']) ? ('回源 IP：' . $rule['out_source_ip']) : '回源 IP：自动');
            echo '<tr data-forward-rule-row="' . (int) $rule['id'] . '" data-server-id="' . (int) ($rule['server_id'] ?? 0) . '">';
            echo '<td>' . (int) $rule['id'] . '</td>';
            echo '<td><strong>' . htmlspecialchars($rule['rule_name'], ENT_QUOTES, 'UTF-8') . '</strong><br><small>' . htmlspecialchars($rule['server_label'] ?: '-', ENT_QUOTES, 'UTF-8') . '</small></td>';
            echo '<td>' . htmlspecialchars($rule['in_endpoint'], ENT_QUOTES, 'UTF-8') . '</td>';
            echo '<td>' . htmlspecialchars($rule['out_endpoint'], ENT_QUOTES, 'UTF-8') . '<br><small>' . htmlspecialchars($ruleSourceMeta, ENT_QUOTES, 'UTF-8') . '</small></td>';
            echo '<td><span class="label label-info">' . htmlspecialchars($rule['protocol'], ENT_QUOTES, 'UTF-8') . '</span></td>';
            echo '<td>' . htmlspecialchars($rule['tag'] ?: '-', ENT_QUOTES, 'UTF-8') . '</td>';
            echo '<td><span class="label forward-admin-status label-' . htmlspecialchars($rule['status_class'], ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($rule['status_text'], ENT_QUOTES, 'UTF-8') . '</span></td>';
            echo '<td>' . (int) $rule['user_id'] . '</td>';
            echo '<td><button type="button" class="btn btn-xs btn-' . ($rule['enabled'] ? 'default' : 'success') . ' forward-toggle-rule" data-id="' . (int) $rule['id'] . '">' . ($rule['enabled'] ? '禁用' : '启用') . '</button> ';
            echo '<button type="button" class="btn btn-xs btn-warning forward-edit-rule" data-rule="' . $ruleJson . '">编辑</button> ';
            echo '<button type="button" class="btn btn-xs btn-danger forward-delete-rule" data-id="' . (int) $rule['id'] . '">删除</button></td>';
            echo '</tr>';
        }
    } else {
        echo '<tr class="forward-admin-empty-row forward-admin-empty-row--all forward-admin-rule-empty-all"><td colspan="9" class="text-center text-muted">暂无规则</td></tr>';
    }
    echo '<tr class="forward-admin-empty-row forward-admin-empty-row--filter forward-admin-rule-empty-filter" style="display:none;"><td colspan="9" class="text-center text-muted">当前宿主机暂无规则</td></tr>';

    echo '</tbody></table></div></div></div>';
    echo '<div class="modal fade" id="forwardAdminRuleModal" tabindex="-1" role="dialog" aria-hidden="true"><div class="modal-dialog" role="document"><div class="modal-content">';
    echo '<form id="forwardAdminRuleForm"><div class="modal-header"><button type="button" class="close" data-dismiss="modal"><span>&times;</span></button><h4 class="modal-title" id="forwardAdminRuleModalTitle">添加规则</h4></div>';
    echo '<div class="modal-body">';
    echo '<input type="hidden" name="rule_id" id="forward_admin_rule_id" value="">';
    echo '<input type="hidden" name="service_id" id="forward_admin_rule_service_id" value="0">';
    echo '<input type="hidden" name="csrf_token" value="' . $csrfToken . '">';
    echo '<div class="form-group"><label for="forward_admin_rule_name">规则名称</label><input type="text" class="form-control" name="rule_name" id="forward_admin_rule_name" required></div>';
    echo '<div class="form-group"><label for="forward_admin_rule_server_id">宿主机</label><select class="form-control" name="server_id" id="forward_admin_rule_server_id" required>' . $adminServerOptionsHtml . '</select><p class="help-block" id="forward_admin_rule_server_help">请选择要下发到哪个宿主机 / Forward 端，再选择入口 IP。</p></div>';
    echo '<div class="form-group"><label for="forward_admin_listen_ip">入口 IP</label><select class="form-control" name="listen_ip" id="forward_admin_listen_ip" required disabled><option value="">请先选择宿主机</option></select></div>';
    echo '<div class="row"><div class="col-sm-6"><div class="form-group"><label for="forward_admin_internal_ip">目标 IP</label><input type="text" class="form-control" name="internal_ip" id="forward_admin_internal_ip" required></div></div>';
    echo '<div class="col-sm-6"><div class="form-group"><label for="forward_admin_internal_port">目标端口</label><input type="number" class="form-control" name="internal_port" id="forward_admin_internal_port" min="1" max="65535" required></div></div></div>';
    echo '<div class="row"><div class="col-sm-6"><div class="form-group"><label for="forward_admin_external_port">入口端口</label><input type="number" class="form-control" name="external_port" id="forward_admin_external_port" min="' . (int) $adminListenPortRange['min'] . '" max="' . (int) $adminListenPortRange['max'] . '" required><p class="help-block">允许范围：' . $adminListenPortRangeText . '</p></div></div>';
    echo '<div class="col-sm-6"><div class="form-group"><label for="forward_admin_protocol">协议</label><select class="form-control" name="protocol" id="forward_admin_protocol" required>' . $protocolSelect . '</select></div></div></div>';
    echo '<div class="form-group"><input type="hidden" name="transparent" value="0"><label class="checkbox-inline"><input type="checkbox" name="transparent" id="forward_admin_rule_transparent" value="1"> 透传客户端源 IP</label><p class="help-block">开启后保留客户端真实源地址；当前仅支持 IPv4 入口与目标 IP 组合，关闭后可选填回源 IP。</p></div>';
    echo '<div class="form-group" id="forward_admin_rule_source_wrap"><label for="forward_admin_rule_out_source_ip">回源 IP</label><input type="text" class="form-control" name="out_source_ip" id="forward_admin_rule_out_source_ip" placeholder="留空表示自动选择"><p class="help-block">仅在关闭透传时生效，必须填写 Forward 宿主机上的本地 IP，且与目标 IP 地址族一致。</p></div>';
    echo '<div class="form-group"><label for="forward_admin_product_name">产品名称</label><input type="text" class="form-control" name="product_name" id="forward_admin_product_name"></div>';
    echo '<div class="form-group"><label for="forward_admin_description">描述</label><textarea class="form-control" name="description" id="forward_admin_description" rows="3"></textarea></div>';
    echo '<div class="alert alert-info" style="margin-bottom:0;">规则会写入 forward 的 <code>/api/rules</code>；多宿主机场景请先明确宿主机，再从该宿主机的入口 IP 池中选择。当前后台入口端口范围：<strong>' . $adminListenPortRangeText . '</strong>。</div>';
    echo '</div><div class="modal-footer"><button type="button" class="btn btn-default" data-dismiss="modal">取消</button><button type="submit" class="btn btn-primary">保存</button></div></form>';
    echo '</div></div></div>';

    echo '<div class="panel panel-default">';
    echo '<div class="panel-heading"><div class="row">';
    echo '<div class="col-sm-6"><strong>共享站点列表（80/443）</strong></div>';
    echo '<div class="col-sm-6 text-right"><button type="button" class="btn btn-primary" id="forwardAddSiteBtn">+ 添加站点</button></div>';
    echo '</div></div><div class="panel-body">';
    echo '<div class="table-responsive"><table class="table table-striped table-bordered">';
    echo '<thead><tr><th>ID</th><th>域名</th><th>监听地址</th><th>后端地址</th><th>标签</th><th>状态</th><th>用户</th><th>操作</th></tr></thead><tbody>';

    if (!empty($sites)) {
        foreach ($sites as $site) {
            $siteJson = htmlspecialchars(json_encode($site, JSON_UNESCAPED_UNICODE), ENT_QUOTES, 'UTF-8');
            $backendHttp = (int) $site['backend_http_port'] > 0 ? ('HTTP:' . (int) $site['backend_http_port']) : 'HTTP:关闭';
            $backendHttps = (int) $site['backend_https_port'] > 0 ? ('HTTPS:' . (int) $site['backend_https_port']) : 'HTTPS:关闭';
            $siteSourceMeta = !empty($site['transparent'])
                ? '源地址：透传'
                : (!empty($site['backend_source_ip']) ? ('回源 IP：' . $site['backend_source_ip']) : '回源 IP：自动');
            echo '<tr data-forward-site-row="' . (int) $site['id'] . '" data-server-id="' . (int) ($site['server_id'] ?? 0) . '">';
            echo '<td>' . (int) $site['id'] . '</td>';
            echo '<td><strong>' . htmlspecialchars($site['domain'], ENT_QUOTES, 'UTF-8') . '</strong><br><small>' . htmlspecialchars($site['server_label'] ?: '-', ENT_QUOTES, 'UTF-8') . '</small></td>';
            echo '<td>' . htmlspecialchars($site['listen_endpoint'], ENT_QUOTES, 'UTF-8') . '</td>';
            echo '<td>' . htmlspecialchars($site['backend_ip'], ENT_QUOTES, 'UTF-8') . ' <small>(' . htmlspecialchars($backendHttp . '，' . $backendHttps, ENT_QUOTES, 'UTF-8') . ')</small><br><small>' . htmlspecialchars($siteSourceMeta, ENT_QUOTES, 'UTF-8') . '</small></td>';
            echo '<td>' . htmlspecialchars($site['tag'] ?: '-', ENT_QUOTES, 'UTF-8') . '</td>';
            echo '<td><span class="label forward-admin-status label-' . htmlspecialchars($site['status_class'], ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($site['status_text'], ENT_QUOTES, 'UTF-8') . '</span></td>';
            echo '<td>' . (int) $site['user_id'] . '</td>';
            echo '<td><button type="button" class="btn btn-xs btn-' . ($site['enabled'] ? 'default' : 'success') . ' forward-toggle-site" data-id="' . (int) $site['id'] . '">' . ($site['enabled'] ? '禁用' : '启用') . '</button> ';
            echo '<button type="button" class="btn btn-xs btn-warning forward-edit-site" data-site="' . $siteJson . '">编辑</button> ';
            echo '<button type="button" class="btn btn-xs btn-danger forward-delete-site" data-id="' . (int) $site['id'] . '">删除</button></td>';
            echo '</tr>';
        }
    } else {
        echo '<tr class="forward-admin-empty-row forward-admin-empty-row--all forward-admin-site-empty-all"><td colspan="8" class="text-center text-muted">暂无共享站点</td></tr>';
    }
    echo '<tr class="forward-admin-empty-row forward-admin-empty-row--filter forward-admin-site-empty-filter" style="display:none;"><td colspan="8" class="text-center text-muted">当前宿主机暂无共享站点</td></tr>';

    echo '</tbody></table></div></div></div>';
    echo '<div class="modal fade" id="forwardAdminSiteModal" tabindex="-1" role="dialog" aria-hidden="true"><div class="modal-dialog" role="document"><div class="modal-content">';
    echo '<form id="forwardAdminSiteForm"><div class="modal-header"><button type="button" class="close" data-dismiss="modal"><span>&times;</span></button><h4 class="modal-title" id="forwardAdminSiteModalTitle">添加共享站点</h4></div>';
    echo '<div class="modal-body">';
    echo '<input type="hidden" name="site_id" id="forward_admin_site_id" value="">';
    echo '<input type="hidden" name="service_id" id="forward_admin_site_service_id" value="0">';
    echo '<input type="hidden" name="csrf_token" value="' . $csrfToken . '">';
    echo '<div class="form-group"><label for="forward_admin_site_domain">域名</label><input type="text" class="form-control" name="domain" id="forward_admin_site_domain" placeholder="例如 app.example.com" required></div>';
    echo '<div class="form-group"><label for="forward_admin_site_server_id">宿主机</label><select class="form-control" name="server_id" id="forward_admin_site_server_id" required>' . $adminServerOptionsHtml . '</select><p class="help-block" id="forward_admin_site_server_help">请选择要下发到哪个宿主机 / Forward 端，再选择入口 IP。</p></div>';
    echo '<div class="form-group"><label for="forward_admin_site_listen_ip">入口 IP</label><select class="form-control" name="listen_ip" id="forward_admin_site_listen_ip" required disabled><option value="">请先选择宿主机</option></select></div>';
    echo '<div class="row"><div class="col-sm-6"><div class="form-group"><label for="forward_admin_site_backend_ip">后端 IP</label><input type="text" class="form-control" name="backend_ip" id="forward_admin_site_backend_ip" required></div></div>';
    echo '<div class="col-sm-6"><div class="form-group"><label for="forward_admin_site_product_name">产品名称</label><input type="text" class="form-control" name="product_name" id="forward_admin_site_product_name"></div></div></div>';
    echo '<div class="row"><div class="col-sm-6"><div class="form-group"><label for="forward_admin_site_http_port">HTTP 端口</label><input type="number" class="form-control" name="backend_http_port" id="forward_admin_site_http_port" min="0" max="65535" value="80"></div></div>';
    echo '<div class="col-sm-6"><div class="form-group"><label for="forward_admin_site_https_port">HTTPS 端口</label><input type="number" class="form-control" name="backend_https_port" id="forward_admin_site_https_port" min="0" max="65535" value="443"></div></div></div>';
    echo '<div class="form-group"><input type="hidden" name="transparent" value="0"><label class="checkbox-inline"><input type="checkbox" name="transparent" id="forward_admin_site_transparent" value="1"> 透传客户端源 IP</label><p class="help-block">开启后保留访客真实源地址；当前仅支持 IPv4 入口与目标 IP 组合，关闭后可选填回源 IP。</p></div>';
    echo '<div class="form-group" id="forward_admin_site_source_wrap"><label for="forward_admin_site_backend_source_ip">回源 IP</label><input type="text" class="form-control" name="backend_source_ip" id="forward_admin_site_backend_source_ip" placeholder="留空表示自动选择"><p class="help-block">仅在关闭透传时生效，必须填写 Forward 宿主机上的本地 IP，且与目标 IP 地址族一致。</p></div>';
    echo '<div class="form-group"><label for="forward_admin_site_description">描述</label><textarea class="form-control" name="description" id="forward_admin_site_description" rows="3"></textarea></div>';
    echo '<div class="alert alert-info" style="margin-bottom:0;">站点会写入 forward 的 <code>/api/sites</code>；多宿主机场景请先明确宿主机，再从该宿主机的入口 IP 池中选择，域名仍需唯一。</div>';
    echo '</div><div class="modal-footer"><button type="button" class="btn btn-default" data-dismiss="modal">取消</button><button type="submit" class="btn btn-primary">保存</button></div></form>';
    echo '</div></div></div>';

    echo '<script>' . PHP_EOL;
    echo '(function ($) {' . PHP_EOL;
    echo '  var csrfToken = ' . $csrfTokenJs . ';' . PHP_EOL;
    echo '  var adminServerOptions = ' . $adminServerOptionsJs . ';' . PHP_EOL;
    echo '  var adminDefaultTransparent = ' . $adminDefaultTransparentJs . ';' . PHP_EOL;
    echo <<<'HTML'

  function normalizeServerId(value) {
    var parsed = parseInt(value, 10);
    return isNaN(parsed) ? 0 : parsed;
  }

  function selectedAdminViewServerId() {
    var value = $('#forwardAdminServerFilter').val();
    return value === null || typeof value === 'undefined' ? '' : String(value);
  }

  function applyAdminServerFilter() {
    var selected = selectedAdminViewServerId();
    var selectedKey = selected === '' ? '' : String(normalizeServerId(selected));
    var $ruleRows = $('[data-forward-rule-row]');
    var $siteRows = $('[data-forward-site-row]');
    var visibleRules = 0;
    var visibleSites = 0;

    $ruleRows.each(function () {
      var match = selectedKey === '' || String(normalizeServerId($(this).data('server-id'))) === selectedKey;
      $(this).toggle(match);
      if (match) {
        visibleRules++;
      }
    });

    $siteRows.each(function () {
      var match = selectedKey === '' || String(normalizeServerId($(this).data('server-id'))) === selectedKey;
      $(this).toggle(match);
      if (match) {
        visibleSites++;
      }
    });

    $('.forward-admin-rule-empty-all').toggle(selectedKey === '' && $ruleRows.length === 0);
    $('.forward-admin-site-empty-all').toggle(selectedKey === '' && $siteRows.length === 0);
    $('.forward-admin-rule-empty-filter').toggle(selectedKey !== '' && $ruleRows.length > 0 && visibleRules === 0);
    $('.forward-admin-site-empty-filter').toggle(selectedKey !== '' && $siteRows.length > 0 && visibleSites === 0);

    var label = selectedKey === '' ? '全部宿主机' : ($('#forwardAdminServerFilter option:selected').text() || ('宿主机 #' + selectedKey));
    $('#forwardAdminServerFilterMeta').text(label + '：规则 ' + visibleRules + ' 条 / 共享站点 ' + visibleSites + ' 个');
  }

  function syncAdminTransparentSource(toggleSelector, sourceSelector, wrapSelector, sourceValue) {
    var $toggle = $(toggleSelector);
    var $source = $(sourceSelector);
    var transparent = $toggle.is(':checked');
    if (typeof sourceValue !== 'undefined') {
      $source.val(sourceValue || '');
    }
    if (transparent) {
      $source.val('');
    }
    $source.prop('disabled', transparent);
    $(wrapSelector).toggle(!transparent);
  }

  function adminServerOption(serverId) {
    var key = String(normalizeServerId(serverId));
    return Object.prototype.hasOwnProperty.call(adminServerOptions, key) ? adminServerOptions[key] : null;
  }

  function ensureSelectOption($select, value) {
    if (!value) {
      return;
    }
    if ($select.find('option[value="' + value.replace(/"/g, '\\"') + '"]').length) {
      return;
    }
    $('<option></option>').val(value).text(value + ' (当前值)').appendTo($select);
  }

  function ensureServerOption($select, serverId, label) {
    var normalized = String(normalizeServerId(serverId));
    if (!normalized) {
      return;
    }
    if ($select.find('option[value="' + normalized + '"]').length) {
      return;
    }
    $('<option></option>')
      .val(normalized)
      .text((label || ('宿主机 #' + normalized)) + ' (当前值)')
      .appendTo($select);
  }

  function populateAdminListenIpSelect($select, serverId, selectedValue) {
    var option = adminServerOption(serverId);
    var ips = option && $.isArray(option.listen_ips) ? option.listen_ips.slice(0) : [];
    var selected = selectedValue || '';
    $select.empty();
    if (!ips.length && selected) {
      ips = [selected];
    }
    if (!ips.length) {
      $('<option></option>').val('').text('请先选择宿主机').appendTo($select);
      $select.prop('disabled', true);
      return;
    }
    $.each(ips, function (_, ip) {
      $('<option></option>').val(ip).text(ip).appendTo($select);
    });
    ensureSelectOption($select, selected);
    $select.prop('disabled', false);
    if (selected && $select.find('option[value="' + selected.replace(/"/g, '\\"') + '"]').length) {
      $select.val(selected);
      return;
    }
    $select.prop('selectedIndex', 0);
  }

  function updateAdminServerHelp($help, serverId) {
    var option = adminServerOption(serverId);
    if (!option) {
      $help.text('请选择要下发到哪个宿主机 / Forward 端，再选择入口 IP。');
      return;
    }
    var listenText = $.isArray(option.listen_ips) && option.listen_ips.length ? option.listen_ips.join(', ') : '未配置';
    var targetText = $.trim(String(option.target_label || '')) || '未配置';
    $help.text('当前宿主机：' + (option.server_label || ('宿主机 #' + normalizeServerId(serverId))) + '；入口 IP：' + listenText + '；Forward 端：' + targetText);
  }

  function syncAdminRuleServer(selectedValue) {
    var serverId = $('#forward_admin_rule_server_id').val();
    populateAdminListenIpSelect($('#forward_admin_listen_ip'), serverId, selectedValue);
    updateAdminServerHelp($('#forward_admin_rule_server_help'), serverId);
  }

  function syncAdminSiteServer(selectedValue) {
    var serverId = $('#forward_admin_site_server_id').val();
    populateAdminListenIpSelect($('#forward_admin_site_listen_ip'), serverId, selectedValue);
    updateAdminServerHelp($('#forward_admin_site_server_help'), serverId);
  }

  function autoSelectSingleServer($select, syncFn) {
    if ($select.find('option').length === 2 && !$select.val()) {
      $select.prop('selectedIndex', 1);
      syncFn();
    }
  }

  function showAdminNotice(type, message, actionLabel, actionHandler) {
    var $notice = $('#forwardAdminNotice');
    $notice
      .removeClass('forward-admin__notice--success forward-admin__notice--warning forward-admin__notice--danger')
      .addClass('forward-admin__notice--' + type)
      .empty();
    $('<span class="forward-admin__notice-text"></span>').text(message).appendTo($notice);
    if (actionLabel && $.isFunction(actionHandler)) {
      $('<button type="button" class="forward-admin__notice-action"></button>')
        .text(actionLabel)
        .on('click', actionHandler)
        .appendTo($notice);
    }
    $notice.stop(true, true).css('display', 'flex').hide().fadeIn(120);
  }

  function showAdminRefreshNotice(message) {
    showAdminNotice('success', message + '，列表未自动刷新。', '刷新列表', function () {
      window.location.reload();
    });
  }

  function setAdminButtonLoading($button, loading, text) {
    if (!$button || !$button.length) {
      return;
    }
    if (!$button.data('default-text')) {
      $button.data('default-text', $.trim($button.text()));
    }
    $button.prop('disabled', loading).toggleClass('is-loading', loading);
    $button.text(loading ? (text || '处理中...') : $button.data('default-text'));
  }

  function setAdminStatus($row, enabled) {
    $row.find('.forward-admin-status').first()
      .removeClass('label-success label-warning label-danger label-default label-info')
      .addClass(enabled ? 'label-success' : 'label-default')
      .text(enabled ? '运行中' : '已停止');
  }

  function setAdminToggleButton($button, enabled) {
    $button
      .removeClass('btn-default btn-success')
      .addClass(enabled ? 'btn-default' : 'btn-success')
      .text(enabled ? '禁用' : '启用')
      .data('default-text', enabled ? '禁用' : '启用');
  }

  function resetForm() {
    $('#forwardAdminRuleForm')[0].reset();
    $('#forward_admin_rule_id').val('');
    $('#forward_admin_rule_service_id').val('0');
    $('#forward_admin_rule_server_id').val('');
    $('#forward_admin_rule_transparent').prop('checked', adminDefaultTransparent);
    syncAdminTransparentSource('#forward_admin_rule_transparent', '#forward_admin_rule_out_source_ip', '#forward_admin_rule_source_wrap', '');
    $('#forwardAdminRuleModalTitle').text('添加规则');
    syncAdminRuleServer('');
    if (selectedAdminViewServerId() !== '' && adminServerOption(selectedAdminViewServerId())) {
      $('#forward_admin_rule_server_id').val(selectedAdminViewServerId());
      syncAdminRuleServer('');
    } else {
      autoSelectSingleServer($('#forward_admin_rule_server_id'), function () { syncAdminRuleServer(''); });
    }
  }

  function resetSiteForm() {
    $('#forwardAdminSiteForm')[0].reset();
    $('#forward_admin_site_id').val('');
    $('#forward_admin_site_service_id').val('0');
    $('#forward_admin_site_server_id').val('');
    $('#forward_admin_site_http_port').val('80');
    $('#forward_admin_site_https_port').val('443');
    $('#forward_admin_site_transparent').prop('checked', adminDefaultTransparent);
    syncAdminTransparentSource('#forward_admin_site_transparent', '#forward_admin_site_backend_source_ip', '#forward_admin_site_source_wrap', '');
    $('#forwardAdminSiteModalTitle').text('添加共享站点');
    syncAdminSiteServer('');
    if (selectedAdminViewServerId() !== '' && adminServerOption(selectedAdminViewServerId())) {
      $('#forward_admin_site_server_id').val(selectedAdminViewServerId());
      syncAdminSiteServer('');
    } else {
      autoSelectSingleServer($('#forward_admin_site_server_id'), function () { syncAdminSiteServer(''); });
    }
  }

  $('#forwardAdminServerFilter').on('change', applyAdminServerFilter);

  $('#forward_admin_rule_server_id').on('change', function () {
    syncAdminRuleServer('');
  });

  $('#forward_admin_site_server_id').on('change', function () {
    syncAdminSiteServer('');
  });

  $('#forward_admin_rule_transparent').on('change', function () {
    syncAdminTransparentSource('#forward_admin_rule_transparent', '#forward_admin_rule_out_source_ip', '#forward_admin_rule_source_wrap');
  });

  $('#forward_admin_site_transparent').on('change', function () {
    syncAdminTransparentSource('#forward_admin_site_transparent', '#forward_admin_site_backend_source_ip', '#forward_admin_site_source_wrap');
  });

  $('#forwardAddRuleBtn').on('click', function () {
    resetForm();
    $('#forwardAdminRuleModal').modal('show');
  });

  $('#forwardAddSiteBtn').on('click', function () {
    resetSiteForm();
    $('#forwardAdminSiteModal').modal('show');
  });

  $('.forward-edit-rule').on('click', function () {
    var rule = $(this).data('rule');
    resetForm();
    $('#forwardAdminRuleModalTitle').text('编辑规则');
    $('#forward_admin_rule_id').val(rule.id || '');
    $('#forward_admin_rule_service_id').val(rule.service_id || 0);
    ensureServerOption($('#forward_admin_rule_server_id'), rule.server_id || 0, rule.server_label || '');
    $('#forward_admin_rule_server_id').val(rule.server_id || 0);
    $('#forward_admin_rule_name').val(rule.rule_name || '');
    syncAdminRuleServer(rule.in_ip || '');
    $('#forward_admin_internal_ip').val(rule.out_ip || '');
    $('#forward_admin_internal_port').val(rule.out_port || '');
    $('#forward_admin_external_port').val(rule.in_port || '');
    $('#forward_admin_protocol').val(rule.protocol || 'tcp');
    $('#forward_admin_rule_transparent').prop('checked', !!rule.transparent);
    syncAdminTransparentSource('#forward_admin_rule_transparent', '#forward_admin_rule_out_source_ip', '#forward_admin_rule_source_wrap', rule.out_source_ip || '');
    $('#forward_admin_product_name').val(rule.product_name || '');
    $('#forward_admin_description').val(rule.description || '');
    $('#forwardAdminRuleModal').modal('show');
  });

  $('.forward-edit-site').on('click', function () {
    var site = $(this).data('site');
    resetSiteForm();
    $('#forwardAdminSiteModalTitle').text('编辑共享站点');
    $('#forward_admin_site_id').val(site.id || '');
    $('#forward_admin_site_service_id').val(site.service_id || 0);
    ensureServerOption($('#forward_admin_site_server_id'), site.server_id || 0, site.server_label || '');
    $('#forward_admin_site_server_id').val(site.server_id || 0);
    $('#forward_admin_site_domain').val(site.domain || '');
    syncAdminSiteServer(site.listen_ip || '');
    $('#forward_admin_site_backend_ip').val(site.backend_ip || '');
    $('#forward_admin_site_http_port').val(site.backend_http_port || 0);
    $('#forward_admin_site_https_port').val(site.backend_https_port || 0);
    $('#forward_admin_site_transparent').prop('checked', !!site.transparent);
    syncAdminTransparentSource('#forward_admin_site_transparent', '#forward_admin_site_backend_source_ip', '#forward_admin_site_source_wrap', site.backend_source_ip || '');
    $('#forward_admin_site_product_name').val(site.product_name || '');
    $('#forward_admin_site_description').val(site.description || '');
    $('#forwardAdminSiteModal').modal('show');
  });

  $('.forward-delete-rule').on('click', function () {
    var $button = $(this);
    var $row = $button.closest('tr');
    var ruleId = $button.data('id');
    if (!confirm('确定删除这条规则吗？')) return;
    setAdminButtonLoading($button, true);
    $.post(window.location.href, {action: 'delete_rule', rule_id: ruleId, csrf_token: csrfToken}, function (response) {
      if (response && response.success) {
        showAdminNotice('success', response.message || '规则已删除');
        $row.addClass('is-removing').fadeOut(180, function () {
          $(this).remove();
          applyAdminServerFilter();
        });
      } else {
        showAdminNotice('danger', response && response.message ? response.message : '删除失败');
      }
    }, 'json').fail(function () {
      showAdminNotice('danger', '删除失败，请稍后重试');
    }).always(function () {
      setAdminButtonLoading($button, false);
    });
  });

  $('.forward-delete-site').on('click', function () {
    var $button = $(this);
    var $row = $button.closest('tr');
    var siteId = $button.data('id');
    if (!confirm('确定删除这个共享站点吗？')) return;
    setAdminButtonLoading($button, true);
    $.post(window.location.href, {action: 'delete_site', site_id: siteId, csrf_token: csrfToken}, function (response) {
      if (response && response.success) {
        showAdminNotice('success', response.message || '共享站点已删除');
        $row.addClass('is-removing').fadeOut(180, function () {
          $(this).remove();
          applyAdminServerFilter();
        });
      } else {
        showAdminNotice('danger', response && response.message ? response.message : '删除失败');
      }
    }, 'json').fail(function () {
      showAdminNotice('danger', '删除失败，请稍后重试');
    }).always(function () {
      setAdminButtonLoading($button, false);
    });
  });

  $('.forward-toggle-rule').on('click', function () {
    var $button = $(this);
    var $row = $button.closest('tr');
    var ruleId = $button.data('id');
    setAdminButtonLoading($button, true);
    $.post(window.location.href, {action: 'toggle_rule', rule_id: ruleId, csrf_token: csrfToken}, function (response) {
      if (response && response.success) {
        var enabled = !!response.enabled;
        setAdminToggleButton($button, enabled);
        setAdminStatus($row, enabled);
        showAdminNotice('success', response.message || '规则状态已更新');
      } else {
        showAdminNotice('danger', response && response.message ? response.message : '切换状态失败');
      }
    }, 'json').fail(function () {
      showAdminNotice('danger', '切换状态失败，请稍后重试');
    }).always(function () {
      setAdminButtonLoading($button, false);
    });
  });

  $('.forward-toggle-site').on('click', function () {
    var $button = $(this);
    var $row = $button.closest('tr');
    var siteId = $button.data('id');
    setAdminButtonLoading($button, true);
    $.post(window.location.href, {action: 'toggle_site', site_id: siteId, csrf_token: csrfToken}, function (response) {
      if (response && response.success) {
        var enabled = !!response.enabled;
        setAdminToggleButton($button, enabled);
        setAdminStatus($row, enabled);
        showAdminNotice('success', response.message || '共享站点状态已更新');
      } else {
        showAdminNotice('danger', response && response.message ? response.message : '切换状态失败');
      }
    }, 'json').fail(function () {
      showAdminNotice('danger', '切换状态失败，请稍后重试');
    }).always(function () {
      setAdminButtonLoading($button, false);
    });
  });

  $('#forwardAdminRuleForm').on('submit', function (e) {
    e.preventDefault();
    var $form = $(this);
    var $submit = $form.find('button[type="submit"]');
    var formData = $form.serializeArray();
    formData.push({name: 'action', value: $('#forward_admin_rule_id').val() ? 'edit_rule' : 'add_rule'});
    setAdminButtonLoading($submit, true, '保存中...');
    $.ajax({
      url: window.location.href,
      type: 'POST',
      data: $.param(formData),
      dataType: 'json'
    }).done(function (response) {
      if (response && response.success) {
        $('#forwardAdminRuleModal').modal('hide');
        showAdminRefreshNotice(response.message || '规则保存成功');
      } else {
        showAdminNotice('danger', response && response.message ? response.message : '保存失败');
      }
    }).fail(function () {
      showAdminNotice('danger', '保存失败，请稍后重试');
    }).always(function () {
      setAdminButtonLoading($submit, false);
    });
  });

  $('#forwardAdminSiteForm').on('submit', function (e) {
    e.preventDefault();
    var $form = $(this);
    var $submit = $form.find('button[type="submit"]');
    var formData = $form.serializeArray();
    formData.push({name: 'action', value: $('#forward_admin_site_id').val() ? 'edit_site' : 'add_site'});
    setAdminButtonLoading($submit, true, '保存中...');
    $.ajax({
      url: window.location.href,
      type: 'POST',
      data: $.param(formData),
      dataType: 'json'
    }).done(function (response) {
      if (response && response.success) {
        $('#forwardAdminSiteModal').modal('hide');
        showAdminRefreshNotice(response.message || '共享站点保存成功');
      } else {
        showAdminNotice('danger', response && response.message ? response.message : '保存失败');
      }
    }).fail(function () {
      showAdminNotice('danger', '保存失败，请稍后重试');
    }).always(function () {
      setAdminButtonLoading($submit, false);
    });
  });

  syncAdminTransparentSource('#forward_admin_rule_transparent', '#forward_admin_rule_out_source_ip', '#forward_admin_rule_source_wrap', '');
  syncAdminTransparentSource('#forward_admin_site_transparent', '#forward_admin_site_backend_source_ip', '#forward_admin_site_source_wrap', '');
  applyAdminServerFilter();
})(jQuery);
</script>
HTML;

    echo '</div>';
    echo '</div>';
}

function forward_clientarea($vars)
{
    try {
        return forward_clientarea_render($vars);
    } catch (Throwable $e) {
        $context = [
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'action' => $_POST['action'] ?? '',
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'file' => $e->getFile(),
            'line' => $e->getLine(),
        ];
        forward_log('clientarea_output_error', $context, $e->getMessage(), $e->getTraceAsString());

        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && !empty($_POST['action'])) {
            forward_json_response(['success' => false, 'message' => 'Forward 客户区操作失败：' . $e->getMessage()]);
        }

        return [
            'pagetitle' => 'Forward',
            'breadcrumb' => ['index.php?m=forward' => 'Forward'],
            'templatefile' => 'clientarea_disabled',
            'requirelogin' => true,
            'vars' => [
                'asset_url' => 'modules/addons/forward',
                'modulelink' => $vars['modulelink'] ?? 'index.php?m=forward',
                'message' => 'Forward 客户区加载失败：' . $e->getMessage(),
            ],
        ];
    }
}

function forward_clientarea_render($vars)
{
    forward_ensure_runtime_schema();

    forward_handle_client_ajax();

    $settings = forward_get_module_settings();
    $enabled = forward_is_enabled_value($settings['enable_client_area'] ?? ($vars['enable_client_area'] ?? 'yes'));
    if (!$enabled) {
        return [
            'pagetitle' => 'Forward',
            'breadcrumb' => ['index.php?m=forward' => 'Forward'],
            'templatefile' => 'clientarea_disabled',
            'requirelogin' => true,
            'vars' => [
                'asset_url' => 'modules/addons/forward',
                'modulelink' => $vars['modulelink'],
                'message' => 'Forward 功能当前未开放。',
            ],
        ];
    }

    $clientId = isset($_SESSION['uid']) ? (int) $_SESSION['uid'] : 0;
    $allowedProducts = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? ($vars['allowed_product_ids'] ?? ''));
    $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? ($vars['allowed_client_ips'] ?? ''));
    $services = $clientId > 0 ? forward_get_user_services($clientId, $allowedProducts, $allowedClientIps, ['Active'], forward_client_service_ip_family($settings)) : [];
    $services = forward_attach_service_listen_ips($services, $settings);
    $hasAccess = $clientId > 0 && !empty($services);
    $rules = $clientId > 0 ? forward_get_local_rules($clientId, false) : [];
    $sites = $clientId > 0 ? forward_get_local_sites($clientId, false) : [];
    if ($hasAccess) {
        $services = forward_attach_service_rule_quotas($services, $settings, $clientId);
        $services = forward_attach_service_site_quotas($services, $settings, $clientId);
    }
    $activeRuleCount = 0;
    foreach ($rules as $rule) {
        if (!empty($rule['enabled'])) {
            $activeRuleCount++;
        }
    }
    $activeSiteCount = 0;
    foreach ($sites as $site) {
        if (!empty($site['enabled'])) {
            $activeSiteCount++;
        }
    }
    $protocols = forward_protocol_options($settings['allowed_protocols'] ?? ($vars['allowed_protocols'] ?? 'tcp+udp'));
    $clientPermissions = forward_client_permissions($settings);
    $maxRules = forward_default_rule_limit($settings);
    $maxSites = forward_default_site_limit($settings ?: ['max_sites_per_user' => ($vars['max_sites_per_user'] ?? 5)]);
    $allServerIps = forward_get_all_server_ips($settings);
    $clientListenPortRange = forward_get_listen_port_range($settings, true);

    if ($clientId > 0 && !$hasAccess) {
        return [
            'pagetitle' => 'Forward',
            'breadcrumb' => ['index.php?m=forward' => 'Forward'],
            'templatefile' => 'clientarea_disabled',
            'requirelogin' => true,
            'vars' => [
                'asset_url' => 'modules/addons/forward',
                'modulelink' => $vars['modulelink'],
                'message' => '您的产品当前未开放 Forward 规则管理。',
            ],
        ];
    }

    return [
        'pagetitle' => 'Forward 管理',
        'breadcrumb' => ['index.php?m=forward' => 'Forward 管理'],
        'templatefile' => 'clientarea',
        'requirelogin' => true,
        'vars' => [
            'asset_url' => 'modules/addons/forward',
            'modulelink' => $vars['modulelink'],
            'is_logged_in' => $clientId > 0,
            'client_id' => $clientId,
            'has_access' => $hasAccess,
            'csrf_token' => forward_get_csrf_token(),
            'rules' => $rules,
            'sites' => $sites,
            'services' => forward_group_services_by_product($services),
            'max_rules' => $maxRules,
            'current_rule_count' => count($rules),
            'active_rule_count' => $activeRuleCount,
            'inactive_rule_count' => count($rules) - $activeRuleCount,
            'can_add_more' => forward_any_service_rule_capacity($services),
            'max_sites' => $maxSites,
            'current_site_count' => count($sites),
            'active_site_count' => $activeSiteCount,
            'inactive_site_count' => count($sites) - $activeSiteCount,
            'can_add_more_sites' => forward_any_service_site_capacity($services),
            'service_ip_count' => forward_count_service_ips($services),
            'allowed_protocols' => $protocols,
            'client_rule_can_edit_listen_ip' => !empty($clientPermissions['rule']['listen_ip']),
            'client_rule_can_edit_protocol' => !empty($clientPermissions['rule']['protocol']),
            'client_rule_can_edit_description' => !empty($clientPermissions['rule']['description']),
            'client_rule_default_protocol' => forward_client_default_rule_protocol($settings),
            'client_site_can_edit_listen_ip' => !empty($clientPermissions['site']['listen_ip']),
            'client_site_can_edit_backend_ports' => !empty($clientPermissions['site']['backend_ports']),
            'client_site_can_edit_description' => !empty($clientPermissions['site']['description']),
            'server_ip' => $allServerIps[0] ?? '0.0.0.0',
            'server_ip_endpoint' => forward_format_ip_for_endpoint($allServerIps[0] ?? '0.0.0.0'),
            'server_ip_summary' => forward_format_ip_list($allServerIps),
            'server_ips' => $allServerIps,
            'client_port_min' => (int) $clientListenPortRange['min'],
            'client_port_max' => (int) $clientListenPortRange['max'],
            'client_port_range_text' => (string) $clientListenPortRange['text'],
        ],
    ];
}
