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
        'version' => '1.0.0',
        'author' => 'OpenAI Codex',
        'language' => 'chinese',
        'fields' => [
            'server_ip' => [
                'FriendlyName' => '默认入口 IP',
                'Type' => 'text',
                'Size' => '50',
                'Description' => '全局默认入口 IP，支持多个 IPv4，用逗号/空格/换行分隔；未命中宿主机映射时使用',
                'Default' => '0.0.0.0',
            ],
            'server_ip_server_map' => [
                'FriendlyName' => '按宿主机映射入口 IP',
                'Type' => 'textarea',
                'Rows' => '5',
                'Description' => "按 WHMCS serverID 指定入口 IP，每行一条，格式如 3=203.0.113.10,203.0.113.11；客户区会按所选服务所属宿主机限制可用入口 IP",
                'Default' => '',
            ],
            'api_endpoint' => [
                'FriendlyName' => 'API 地址',
                'Type' => 'text',
                'Size' => '50',
                'Description' => '例如: http://127.0.0.1:8080',
                'Default' => 'http://127.0.0.1:8080',
            ],
            'api_token' => [
                'FriendlyName' => 'API Token',
                'Type' => 'password',
                'Size' => '50',
                'Description' => 'forward 的 Web Token，会以 Authorization: Bearer <token> 调用',
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
                'Description' => '客户区每个用户最多可创建的规则数量',
                'Default' => '10',
            ],
            'max_sites_per_user' => [
                'FriendlyName' => '每用户最大站点数',
                'Type' => 'text',
                'Size' => '10',
                'Description' => '客户区每个用户最多可创建的共享站点数量',
                'Default' => '5',
            ],
            'allowed_protocols' => [
                'FriendlyName' => '允许的协议',
                'Type' => 'dropdown',
                'Options' => 'tcp,udp,tcp+udp',
                'Description' => '客户区允许选择的协议',
                'Default' => 'tcp+udp',
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
                'Description' => '多个 IPv4 用逗号/空格/换行分隔；留空则不限制（仍受产品 IP 约束）',
                'Default' => '',
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
                $table->string('protocol', 20)->default('tcp');
                $table->string('tag', 100)->default('');
                $table->boolean('transparent')->default(false);
                $table->string('status', 20)->default('active');
                $table->text('description')->nullable();
                $table->timestamp('created_at')->useCurrent();
                $table->timestamp('updated_at')->useCurrent();
                $table->index(['user_id', 'status']);
                $table->index(['in_ip', 'in_port']);
            });
        } else {
            $columns = [
                'forward_rule_id' => function ($table) { $table->unsignedBigInteger('forward_rule_id')->nullable()->unique()->after('id'); },
                'user_id' => function ($table) { $table->integer('user_id')->default(0)->after('forward_rule_id'); },
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
                'protocol' => function ($table) { $table->string('protocol', 20)->default('tcp')->after('out_port'); },
                'tag' => function ($table) { $table->string('tag', 100)->default('')->after('protocol'); },
                'transparent' => function ($table) { $table->boolean('transparent')->default(false)->after('tag'); },
                'status' => function ($table) { $table->string('status', 20)->default('active')->after('transparent'); },
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
                $table->integer('user_id')->default(0);
                $table->string('product_name', 100)->nullable();
                $table->integer('server_id')->default(0);
                $table->integer('service_id')->default(0);
                $table->string('domain', 253);
                $table->string('listen_interface', 100)->default('');
                $table->string('listen_ip', 45)->default('0.0.0.0');
                $table->string('backend_ip', 45);
                $table->integer('backend_http_port')->default(80);
                $table->integer('backend_https_port')->default(443);
                $table->string('tag', 100)->default('');
                $table->boolean('transparent')->default(false);
                $table->string('status', 20)->default('active');
                $table->text('description')->nullable();
                $table->timestamp('created_at')->useCurrent();
                $table->timestamp('updated_at')->useCurrent();
                $table->index(['user_id', 'status']);
                $table->index(['domain']);
                $table->index(['backend_ip']);
            });
        } else {
            $columns = [
                'forward_site_id' => function ($table) { $table->unsignedBigInteger('forward_site_id')->nullable()->unique()->after('id'); },
                'user_id' => function ($table) { $table->integer('user_id')->default(0)->after('forward_site_id'); },
                'product_name' => function ($table) { $table->string('product_name', 100)->nullable()->after('user_id'); },
                'server_id' => function ($table) { $table->integer('server_id')->default(0)->after('product_name'); },
                'service_id' => function ($table) { $table->integer('service_id')->default(0)->after('server_id'); },
                'domain' => function ($table) { $table->string('domain', 253)->default('')->after('service_id'); },
                'listen_interface' => function ($table) { $table->string('listen_interface', 100)->default('')->after('domain'); },
                'listen_ip' => function ($table) { $table->string('listen_ip', 45)->default('0.0.0.0')->after('listen_interface'); },
                'backend_ip' => function ($table) { $table->string('backend_ip', 45)->default('')->after('listen_ip'); },
                'backend_http_port' => function ($table) { $table->integer('backend_http_port')->default(80)->after('backend_ip'); },
                'backend_https_port' => function ($table) { $table->integer('backend_https_port')->default(443)->after('backend_http_port'); },
                'tag' => function ($table) { $table->string('tag', 100)->default('')->after('backend_https_port'); },
                'transparent' => function ($table) { $table->boolean('transparent')->default(false)->after('tag'); },
                'status' => function ($table) { $table->string('status', 20)->default('active')->after('transparent'); },
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
    } catch (Exception $e) {
        forward_log('ensure_runtime_schema_error', [], $e->getMessage());
    }

    forward_backfill_local_service_bindings();
}

function forward_log($action, $request = null, $response = null, $processed = '')
{
    logModuleCall('forward', $action, $request, $response, $processed);
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
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

function forward_ips_conflict($leftIp, $rightIp)
{
    $left = trim((string) $leftIp);
    $right = trim((string) $rightIp);
    if ($left === '' || $right === '') {
        return false;
    }
    return $left === $right || $left === '0.0.0.0' || $right === '0.0.0.0';
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

function forward_parse_allowed_client_ips($value)
{
    $raw = preg_split('/[\s,]+/', (string) $value, -1, PREG_SPLIT_NO_EMPTY);
    $ips = [];
    foreach ($raw as $item) {
        $ip = trim((string) $item);
        if (forward_is_valid_ipv4($ip)) {
            $ips[] = $ip;
        }
    }
    return array_values(array_unique($ips));
}

function forward_parse_server_ips($value)
{
    $raw = preg_split('/[\s,]+/', (string) $value, -1, PREG_SPLIT_NO_EMPTY);
    $ips = [];
    foreach ($raw as $item) {
        $ip = trim((string) $item);
        if (forward_is_valid_ipv4($ip)) {
            $ips[] = $ip;
        }
    }
    return array_values(array_unique($ips));
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
    if (!empty($mappedIps)) {
        return [];
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

function forward_pick_listen_ip($value, array $allowedIps)
{
    $listenIp = trim((string) $value);
    if ($listenIp === '') {
        return $allowedIps[0] ?? '';
    }
    return in_array($listenIp, $allowedIps, true) ? $listenIp : '';
}

function forward_format_ip_list(array $ips)
{
    return implode(', ', array_values(array_unique($ips)));
}

function forward_attach_service_listen_ips(array $services, array $settings)
{
    $result = [];
    foreach ($services as $service) {
        $listenIps = forward_get_allowed_server_ips($settings, (int) ($service['server_id'] ?? 0));
        if (empty($listenIps)) {
            continue;
        }
        $service['listen_ips'] = $listenIps;
        $service['listen_ips_csv'] = implode(',', $listenIps);
        $result[] = $service;
    }
    return $result;
}

function forward_get_user_services($userId, array $allowedProductIds = [], array $allowedClientIps = [])
{
    try {
        $query = Capsule::table('tblhosting')
            ->join('tblproducts', 'tblhosting.packageid', '=', 'tblproducts.id')
            ->leftJoin('tblservers', 'tblhosting.server', '=', 'tblservers.id')
            ->where('tblhosting.userid', (int) $userId)
            ->whereIn('tblhosting.domainstatus', ['Active', 'Suspended'])
            ->select(
                'tblhosting.id as service_id',
                'tblhosting.server as server_id',
                'tblhosting.packageid as product_id',
                'tblhosting.dedicatedip',
                'tblhosting.assignedips',
                'tblproducts.name as product_name',
                'tblproducts.gid as product_group_id',
                'tblservers.name as server_name',
                'tblservers.hostname as server_hostname'
            );

        if (!empty($allowedProductIds)) {
            $query->whereIn('tblhosting.packageid', $allowedProductIds);
        }

        $rows = $query->get();
        $services = [];
        foreach ($rows as $row) {
            $ips = [];
            if (!empty($row->dedicatedip)) {
                $ips[] = trim($row->dedicatedip);
            }
            if (!empty($row->assignedips)) {
                $parts = preg_split('/[\r\n,\s]+/', $row->assignedips, -1, PREG_SPLIT_NO_EMPTY);
                foreach ($parts as $part) {
                    $ips[] = trim($part);
                }
            }
            $ips = array_values(array_unique(array_filter($ips, 'forward_is_valid_ipv4')));
            if (!empty($allowedClientIps)) {
                $ips = array_values(array_intersect($ips, $allowedClientIps));
            }
            if (empty($ips)) {
                continue;
            }
            $services[] = [
                'service_id' => (int) $row->service_id,
                'server_id' => (int) $row->server_id,
                'server_label' => forward_format_server_label($row->server_id, $row->server_name ?? '', $row->server_hostname ?? ''),
                'product_id' => (int) $row->product_id,
                'product_group_id' => (int) $row->product_group_id,
                'product_name' => $row->product_name,
                'ips' => $ips,
            ];
        }
        return $services;
    } catch (Exception $e) {
        forward_log('get_user_services_error', ['user_id' => $userId], $e->getMessage());
        return [];
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
    $ip = trim((string) $ip);
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
                    $serviceCache[$userId] = forward_get_user_services($userId);
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

function forward_call_api($path, $method = 'GET', array $payload = null)
{
    $config = forward_get_module_settings();
    $endpoint = rtrim((string) ($config['api_endpoint'] ?? ''), '/');
    $token = (string) ($config['api_token'] ?? '');
    $skipTlsVerify = forward_is_enabled_value($config['skip_tls_verify'] ?? 'off');

    if ($endpoint === '') {
        return ['success' => false, 'message' => '未配置 API 地址'];
    }
    if ($token === '') {
        return ['success' => false, 'message' => '未配置 API Token'];
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
            : ['success' => false, 'message' => 'API 返回空响应，HTTP 状态码: ' . $status];
    }

    $decoded = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ($status >= 200 && $status < 300)
            ? ['success' => true, 'data' => $response]
            : ['success' => false, 'message' => 'API 返回异常内容: ' . $response];
    }

    if ($status < 200 || $status >= 300) {
        $message = $decoded['error'] ?? $decoded['message'] ?? ('HTTP ' . $status);
        return ['success' => false, 'message' => $message, 'data' => $decoded];
    }

    return ['success' => true, 'data' => $decoded];
}

function forward_status_meta(array $remote = null, $localStatus = 'active')
{
    if ($remote === null) {
        if ($localStatus === 'inactive') {
            return ['text' => '已禁用', 'class' => 'default'];
        }
        return ['text' => '本地记录', 'class' => 'info'];
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

function forward_get_remote_rule_map()
{
    $result = forward_call_api('/api/rules', 'GET');
    if (!$result['success'] || !is_array($result['data'])) {
        return [];
    }

    $map = [];
    foreach ($result['data'] as $rule) {
        if (isset($rule['id'])) {
            $map[(int) $rule['id']] = $rule;
        }
    }
    return $map;
}

function forward_get_local_rules($userId = null)
{
    $query = Capsule::table('mod_forward_rules')->orderBy('created_at', 'desc');
    if ($userId !== null) {
        $query->where('user_id', (int) $userId);
    }

    $rows = $query->get();
    $remoteMap = forward_get_remote_rule_map();
    $result = [];

    foreach ($rows as $row) {
        $remote = null;
        if (!empty($row->forward_rule_id) && isset($remoteMap[(int) $row->forward_rule_id])) {
            $remote = $remoteMap[(int) $row->forward_rule_id];
        }
        $statusMeta = forward_status_meta($remote, $row->status);
        $result[] = [
            'id' => (int) $row->id,
            'forward_rule_id' => $row->forward_rule_id ? (int) $row->forward_rule_id : 0,
            'user_id' => (int) $row->user_id,
            'product_name' => $row->product_name ?: '',
            'server_id' => (int) ($row->server_id ?? 0),
            'service_id' => (int) ($row->service_id ?? 0),
            'server_label' => forward_get_server_label($row->server_id ?? 0),
            'rule_name' => $row->rule_name,
            'in_interface' => $row->in_interface ?: '',
            'in_ip' => $row->in_ip,
            'in_port' => (int) $row->in_port,
            'out_interface' => $row->out_interface ?: '',
            'out_ip' => $row->out_ip,
            'out_port' => (int) $row->out_port,
            'protocol' => $row->protocol,
            'tag' => $row->tag ?: '',
            'transparent' => (bool) $row->transparent,
            'status' => $row->status,
            'description' => $row->description ?: '',
            'created_at' => $row->created_at,
            'updated_at' => $row->updated_at,
            'remote_status' => $remote['status'] ?? '',
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

function forward_has_remote_conflict($listenIp, $inPort, $protocol, $excludeRemoteRuleId = 0)
{
    $remoteMap = forward_get_remote_rule_map();
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

    $remoteMap = forward_get_remote_rule_map();
    $remote = (!empty($row->forward_rule_id) && isset($remoteMap[(int) $row->forward_rule_id]))
        ? $remoteMap[(int) $row->forward_rule_id]
        : null;
    $statusMeta = forward_status_meta($remote, $row->status);

    return [
        'id' => (int) $row->id,
        'forward_rule_id' => $row->forward_rule_id ? (int) $row->forward_rule_id : 0,
        'user_id' => (int) $row->user_id,
        'product_name' => $row->product_name ?: '',
        'server_id' => (int) ($row->server_id ?? 0),
        'service_id' => (int) ($row->service_id ?? 0),
        'server_label' => forward_get_server_label($row->server_id ?? 0),
        'rule_name' => $row->rule_name,
        'in_interface' => $row->in_interface ?: '',
        'in_ip' => $row->in_ip,
        'in_port' => (int) $row->in_port,
        'out_interface' => $row->out_interface ?: '',
        'out_ip' => $row->out_ip,
        'out_port' => (int) $row->out_port,
        'protocol' => $row->protocol,
        'tag' => $row->tag ?: '',
        'transparent' => (bool) $row->transparent,
        'status' => $row->status,
        'description' => $row->description ?: '',
        'status_text' => $statusMeta['text'],
        'status_class' => $statusMeta['class'],
    ];
}

function forward_validate_rule_input(array $data, array $settings, $isClient = false, $excludeLocalRuleId = 0, $excludeRemoteRuleId = 0, array $allowedListenIps = null)
{
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

    $outIp = trim((string) ($data['internal_ip'] ?? $data['out_ip'] ?? ''));
    if (!forward_is_valid_ipv4($outIp)) {
        return ['success' => false, 'message' => '目标 IP 必须是有效的 IPv4 地址'];
    }

    $outPort = (int) ($data['internal_port'] ?? $data['out_port'] ?? 0);
    if ($outPort < 1 || $outPort > 65535) {
        return ['success' => false, 'message' => '目标端口必须在 1-65535 之间'];
    }

    $inPort = (int) ($data['external_port'] ?? $data['in_port'] ?? 0);
    $minListenPort = $isClient ? 10000 : 1;
    if ($inPort < $minListenPort || $inPort > 65535) {
        return ['success' => false, 'message' => '入口端口必须在 ' . $minListenPort . '-65535 之间'];
    }

    $allowedProtocols = forward_protocol_options($settings['allowed_protocols'] ?? 'tcp+udp');
    $protocol = forward_normalize_protocol($data['protocol'] ?? '');
    if ($protocol === '' || !in_array($protocol, $allowedProtocols, true)) {
        return ['success' => false, 'message' => '不支持的协议类型'];
    }

    $conflictQuery = Capsule::table('mod_forward_rules')
        ->where('in_port', $inPort)
        ->whereIn('protocol', forward_protocol_conflicts($protocol));

    if ($listenIp !== '0.0.0.0') {
        $conflictQuery->whereIn('in_ip', [$listenIp, '0.0.0.0']);
    }

    if ($excludeLocalRuleId > 0) {
        $conflictQuery->where('id', '!=', (int) $excludeLocalRuleId);
    }

    if ($conflictQuery->first()) {
        return ['success' => false, 'message' => '该入口端口已在模块中被占用'];
    }

    if (forward_has_remote_conflict($listenIp, $inPort, $protocol, $excludeRemoteRuleId)) {
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
            'in_interface' => trim((string) ($settings['in_interface'] ?? '')),
            'in_ip' => $listenIp,
            'listen_ips' => $listenIps,
            'in_port' => $inPort,
            'out_interface' => trim((string) ($settings['out_interface'] ?? '')),
            'out_ip' => $outIp,
            'out_port' => $outPort,
            'protocol' => $protocol,
            'tag' => trim((string) ($settings['default_tag'] ?? '')),
            'transparent' => forward_is_enabled_value($settings['transparent_mode'] ?? 'off'),
            'description' => $description,
            'product_name' => $productName,
        ],
    ];
}

function forward_create_rule(array $data, $userId = 0, $isClient = false)
{
    $settings = forward_get_module_settings();
    $service = null;
    $allowedListenIps = null;
    if ($isClient) {
        $allowedProducts = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
        $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
        $services = forward_get_user_services($userId, $allowedProducts, $allowedClientIps);
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
    }

    $validated = forward_validate_rule_input($data, $settings, $isClient, 0, 0, $allowedListenIps);
    if (!$validated['success']) {
        return $validated;
    }

    $rule = $validated['data'];

    if ($isClient) {
        $maxRules = max(0, (int) ($settings['max_rules_per_user'] ?? 0));
        if ($maxRules > 0) {
            $currentCount = (int) Capsule::table('mod_forward_rules')->where('user_id', (int) $userId)->count();
            if ($currentCount >= $maxRules) {
                return ['success' => false, 'message' => '已达到最大规则数量限制'];
            }
        }

        $rule['product_name'] = $service['product_name'];
    }

    $payload = [
        'in_interface' => $rule['in_interface'],
        'in_ip' => $rule['in_ip'],
        'in_port' => $rule['in_port'],
        'out_interface' => $rule['out_interface'],
        'out_ip' => $rule['out_ip'],
        'out_port' => $rule['out_port'],
        'protocol' => $rule['protocol'],
        'remark' => $rule['rule_name'],
        'tag' => $rule['tag'],
        'transparent' => $rule['transparent'],
    ];

    $api = forward_call_api('/api/rules', 'POST', $payload);
    if (!$api['success']) {
        return ['success' => false, 'message' => '后端创建规则失败：' . $api['message']];
    }

    $remoteId = (int) ($api['data']['id'] ?? 0);
    Capsule::table('mod_forward_rules')->insert([
        'forward_rule_id' => $remoteId > 0 ? $remoteId : null,
        'user_id' => (int) $userId,
        'product_name' => $rule['product_name'] ?: null,
        'server_id' => is_array($service) ? (int) ($service['server_id'] ?? 0) : 0,
        'service_id' => is_array($service) ? (int) ($service['service_id'] ?? 0) : 0,
        'rule_name' => $rule['rule_name'],
        'in_interface' => $rule['in_interface'],
        'in_ip' => $rule['in_ip'],
        'in_port' => $rule['in_port'],
        'out_interface' => $rule['out_interface'],
        'out_ip' => $rule['out_ip'],
        'out_port' => $rule['out_port'],
        'protocol' => $rule['protocol'],
        'tag' => $rule['tag'],
        'transparent' => $rule['transparent'] ? 1 : 0,
        'status' => 'active',
        'description' => $rule['description'],
        'created_at' => date('Y-m-d H:i:s'),
        'updated_at' => date('Y-m-d H:i:s'),
    ]);

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

    if ($userId !== null) {
        $data['internal_ip'] = $existing->out_ip;
    }

    $settings = forward_get_module_settings();
    $service = null;
    $allowedListenIps = null;
    if ($userId !== null) {
        $allowedProducts = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
        $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
        $services = forward_get_user_services($userId, $allowedProducts, $allowedClientIps);
        $existingServiceId = (int) ($existing->service_id ?? 0);
        $existingServerId = (int) ($existing->server_id ?? 0);
        $service = forward_find_service_for_ip(
            $services,
            trim((string) ($data['internal_ip'] ?? $data['out_ip'] ?? '')),
            $existingServiceId > 0 ? $existingServiceId : (int) ($data['service_id'] ?? 0),
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
    }
    $validated = forward_validate_rule_input(
        $data,
        $settings,
        $userId !== null,
        $ruleId,
        (int) ($existing->forward_rule_id ?? 0),
        $allowedListenIps
    );
    if (!$validated['success']) {
        return $validated;
    }

    $rule = $validated['data'];
    if ($userId !== null) {
        $rule['product_name'] = $service['product_name'];
    }

    $payload = [
        'id' => (int) $existing->forward_rule_id,
        'in_interface' => $rule['in_interface'],
        'in_ip' => $rule['in_ip'],
        'in_port' => $rule['in_port'],
        'out_interface' => $rule['out_interface'],
        'out_ip' => $rule['out_ip'],
        'out_port' => $rule['out_port'],
        'protocol' => $rule['protocol'],
        'remark' => $rule['rule_name'],
        'tag' => $rule['tag'],
        'transparent' => $rule['transparent'],
    ];

    if (!empty($existing->forward_rule_id)) {
        $api = forward_call_api('/api/rules', 'PUT', $payload);
    } else {
        unset($payload['id']);
        $api = forward_call_api('/api/rules', 'POST', $payload);
    }

    if (!$api['success']) {
        return ['success' => false, 'message' => '后端更新规则失败：' . $api['message']];
    }

    $remoteId = !empty($existing->forward_rule_id)
        ? (int) $existing->forward_rule_id
        : (int) ($api['data']['id'] ?? 0);

    Capsule::table('mod_forward_rules')
        ->where('id', $ruleId)
        ->update([
            'forward_rule_id' => $remoteId > 0 ? $remoteId : null,
            'product_name' => $rule['product_name'] ?: null,
            'server_id' => $userId !== null
                ? (is_array($service) ? (int) ($service['server_id'] ?? 0) : 0)
                : (int) ($data['server_id'] ?? $existing->server_id ?? 0),
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
            'protocol' => $rule['protocol'],
            'tag' => $rule['tag'],
            'transparent' => $rule['transparent'] ? 1 : 0,
            'description' => $rule['description'],
            'updated_at' => date('Y-m-d H:i:s'),
        ]);

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

    $enabled = $existing->status !== 'inactive';
    if (!empty($existing->forward_rule_id)) {
        $api = forward_call_api('/api/rules/toggle?id=' . urlencode((string) $existing->forward_rule_id), 'POST');
        if (!$api['success']) {
            return ['success' => false, 'message' => '后端切换规则状态失败：' . $api['message']];
        }
        if (isset($api['data']['enabled'])) {
            $enabled = (bool) $api['data']['enabled'];
        } else {
            $enabled = !$enabled;
        }
    } else {
        $enabled = !$enabled;
    }

    Capsule::table('mod_forward_rules')
        ->where('id', (int) $ruleId)
        ->update([
            'status' => $enabled ? 'active' : 'inactive',
            'updated_at' => date('Y-m-d H:i:s'),
        ]);

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

    if (!empty($existing->forward_rule_id)) {
        $api = forward_call_api('/api/rules?id=' . urlencode((string) $existing->forward_rule_id), 'DELETE');
        if (!$api['success']) {
            $message = strtolower((string) $api['message']);
            if (strpos($message, 'not found') === false && strpos($message, '不存在') === false) {
                return ['success' => false, 'message' => '后端删除规则失败：' . $api['message']];
            }
        }
    }

    Capsule::table('mod_forward_rules')->where('id', (int) $ruleId)->delete();
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

function forward_get_remote_site_map()
{
    $result = forward_call_api('/api/sites', 'GET');
    if (!$result['success'] || !is_array($result['data'])) {
        return [];
    }

    $map = [];
    foreach ($result['data'] as $site) {
        if (isset($site['id'])) {
            $map[(int) $site['id']] = $site;
        }
    }
    return $map;
}

function forward_get_local_sites($userId = null)
{
    $query = Capsule::table('mod_forward_sites')->orderBy('created_at', 'desc');
    if ($userId !== null) {
        $query->where('user_id', (int) $userId);
    }

    $rows = $query->get();
    $remoteMap = forward_get_remote_site_map();
    $result = [];

    foreach ($rows as $row) {
        $remote = null;
        if (!empty($row->forward_site_id) && isset($remoteMap[(int) $row->forward_site_id])) {
            $remote = $remoteMap[(int) $row->forward_site_id];
        }
        $statusMeta = forward_status_meta($remote, $row->status);
        $result[] = [
            'id' => (int) $row->id,
            'forward_site_id' => $row->forward_site_id ? (int) $row->forward_site_id : 0,
            'user_id' => (int) $row->user_id,
            'product_name' => $row->product_name ?: '',
            'server_id' => (int) ($row->server_id ?? 0),
            'service_id' => (int) ($row->service_id ?? 0),
            'server_label' => forward_get_server_label($row->server_id ?? 0),
            'domain' => $row->domain,
            'listen_interface' => $row->listen_interface ?: '',
            'listen_ip' => $row->listen_ip,
            'backend_ip' => $row->backend_ip,
            'backend_http_port' => (int) $row->backend_http_port,
            'backend_https_port' => (int) $row->backend_https_port,
            'tag' => $row->tag ?: '',
            'transparent' => (bool) $row->transparent,
            'status' => $row->status,
            'description' => $row->description ?: '',
            'created_at' => $row->created_at,
            'updated_at' => $row->updated_at,
            'remote_status' => $remote['status'] ?? '',
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

    $remoteMap = forward_get_remote_site_map();
    $remote = (!empty($row->forward_site_id) && isset($remoteMap[(int) $row->forward_site_id]))
        ? $remoteMap[(int) $row->forward_site_id]
        : null;
    $statusMeta = forward_status_meta($remote, $row->status);

    return [
        'id' => (int) $row->id,
        'forward_site_id' => $row->forward_site_id ? (int) $row->forward_site_id : 0,
        'user_id' => (int) $row->user_id,
        'product_name' => $row->product_name ?: '',
        'server_id' => (int) ($row->server_id ?? 0),
        'service_id' => (int) ($row->service_id ?? 0),
        'server_label' => forward_get_server_label($row->server_id ?? 0),
        'domain' => $row->domain,
        'listen_interface' => $row->listen_interface ?: '',
        'listen_ip' => $row->listen_ip,
        'backend_ip' => $row->backend_ip,
        'backend_http_port' => (int) $row->backend_http_port,
        'backend_https_port' => (int) $row->backend_https_port,
        'tag' => $row->tag ?: '',
        'transparent' => (bool) $row->transparent,
        'status' => $row->status,
        'description' => $row->description ?: '',
        'status_text' => $statusMeta['text'],
        'status_class' => $statusMeta['class'],
    ];
}

function forward_has_remote_site_conflict($domain, $excludeRemoteSiteId = 0)
{
    $normalizedDomain = forward_normalize_domain($domain);
    $remoteMap = forward_get_remote_site_map();
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

function forward_validate_site_input(array $data, array $settings, $excludeLocalSiteId = 0, $excludeRemoteSiteId = 0, array $allowedListenIps = null)
{
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

    $backendIp = trim((string) ($data['backend_ip'] ?? $data['internal_ip'] ?? ''));
    if (!forward_is_valid_ipv4($backendIp)) {
        return ['success' => false, 'message' => '目标 IP 必须是有效的 IPv4 地址'];
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

    $productName = trim((string) ($data['product_name'] ?? ''));
    if (forward_strlen($productName) > 100) {
        return ['success' => false, 'message' => '产品名称不能超过 100 个字符'];
    }

    $description = trim((string) ($data['description'] ?? ''));
    if (forward_strlen($description) > 2000) {
        return ['success' => false, 'message' => '描述不能超过 2000 个字符'];
    }

    $conflictQuery = Capsule::table('mod_forward_sites')->where('domain', $domain);
    if ($excludeLocalSiteId > 0) {
        $conflictQuery->where('id', '!=', (int) $excludeLocalSiteId);
    }
    if ($conflictQuery->first()) {
        return ['success' => false, 'message' => '该域名已在模块中存在'];
    }

    if (forward_has_remote_site_conflict($domain, $excludeRemoteSiteId)) {
        return ['success' => false, 'message' => '该域名已在 forward 中被其他站点占用'];
    }

    return [
        'success' => true,
        'data' => [
            'domain' => $domain,
            'listen_interface' => trim((string) ($settings['in_interface'] ?? '')),
            'listen_ip' => $listenIp,
            'listen_ips' => $listenIps,
            'backend_ip' => $backendIp,
            'backend_http_port' => $backendHttpPort,
            'backend_https_port' => $backendHttpsPort,
            'tag' => trim((string) ($settings['default_tag'] ?? '')),
            'transparent' => forward_is_enabled_value($settings['transparent_mode'] ?? 'off'),
            'description' => $description,
            'product_name' => $productName,
        ],
    ];
}

function forward_create_site(array $data, $userId = 0, $isClient = false)
{
    $settings = forward_get_module_settings();
    $service = null;
    $allowedListenIps = null;
    if ($isClient) {
        $allowedProducts = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
        $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
        $services = forward_get_user_services($userId, $allowedProducts, $allowedClientIps);
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
    }

    $validated = forward_validate_site_input($data, $settings, 0, 0, $allowedListenIps);
    if (!$validated['success']) {
        return $validated;
    }

    $site = $validated['data'];

    if ($isClient) {
        $maxSites = max(0, (int) ($settings['max_sites_per_user'] ?? 0));
        if ($maxSites > 0) {
            $currentCount = (int) Capsule::table('mod_forward_sites')->where('user_id', (int) $userId)->count();
            if ($currentCount >= $maxSites) {
                return ['success' => false, 'message' => '已达到最大共享站点数量限制'];
            }
        }

        $site['product_name'] = $service['product_name'];
    }

    $payload = [
        'domain' => $site['domain'],
        'listen_interface' => $site['listen_interface'],
        'listen_ip' => $site['listen_ip'],
        'backend_ip' => $site['backend_ip'],
        'backend_http_port' => $site['backend_http_port'],
        'backend_https_port' => $site['backend_https_port'],
        'tag' => $site['tag'],
        'transparent' => $site['transparent'],
    ];

    $api = forward_call_api('/api/sites', 'POST', $payload);
    if (!$api['success']) {
        return ['success' => false, 'message' => '后端创建站点失败：' . $api['message']];
    }

    $remoteId = (int) ($api['data']['id'] ?? 0);
    Capsule::table('mod_forward_sites')->insert([
        'forward_site_id' => $remoteId > 0 ? $remoteId : null,
        'user_id' => (int) $userId,
        'product_name' => $site['product_name'] ?: null,
        'server_id' => is_array($service) ? (int) ($service['server_id'] ?? 0) : 0,
        'service_id' => is_array($service) ? (int) ($service['service_id'] ?? 0) : 0,
        'domain' => $site['domain'],
        'listen_interface' => $site['listen_interface'],
        'listen_ip' => $site['listen_ip'],
        'backend_ip' => $site['backend_ip'],
        'backend_http_port' => $site['backend_http_port'],
        'backend_https_port' => $site['backend_https_port'],
        'tag' => $site['tag'],
        'transparent' => $site['transparent'] ? 1 : 0,
        'status' => 'active',
        'description' => $site['description'],
        'created_at' => date('Y-m-d H:i:s'),
        'updated_at' => date('Y-m-d H:i:s'),
    ]);

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
    $service = null;
    $allowedListenIps = null;
    if ($userId !== null) {
        $allowedProducts = forward_parse_allowed_product_ids($settings['allowed_product_ids'] ?? '');
        $allowedClientIps = forward_parse_allowed_client_ips($settings['allowed_client_ips'] ?? '');
        $services = forward_get_user_services($userId, $allowedProducts, $allowedClientIps);
        $existingServiceId = (int) ($existing->service_id ?? 0);
        $existingServerId = (int) ($existing->server_id ?? 0);
        $service = forward_find_service_for_ip(
            $services,
            trim((string) ($data['backend_ip'] ?? $data['internal_ip'] ?? '')),
            $existingServiceId > 0 ? $existingServiceId : (int) ($data['service_id'] ?? 0),
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
    }
    $validated = forward_validate_site_input(
        $data,
        $settings,
        $siteId,
        (int) ($existing->forward_site_id ?? 0),
        $allowedListenIps
    );
    if (!$validated['success']) {
        return $validated;
    }

    $site = $validated['data'];
    if ($userId !== null) {
        $site['product_name'] = $service['product_name'];
    }

    $payload = [
        'id' => (int) $existing->forward_site_id,
        'domain' => $site['domain'],
        'listen_interface' => $site['listen_interface'],
        'listen_ip' => $site['listen_ip'],
        'backend_ip' => $site['backend_ip'],
        'backend_http_port' => $site['backend_http_port'],
        'backend_https_port' => $site['backend_https_port'],
        'tag' => $site['tag'],
        'transparent' => $site['transparent'],
    ];

    if (!empty($existing->forward_site_id)) {
        $api = forward_call_api('/api/sites', 'PUT', $payload);
    } else {
        unset($payload['id']);
        $api = forward_call_api('/api/sites', 'POST', $payload);
    }

    if (!$api['success']) {
        return ['success' => false, 'message' => '后端更新站点失败：' . $api['message']];
    }

    $remoteId = !empty($existing->forward_site_id)
        ? (int) $existing->forward_site_id
        : (int) ($api['data']['id'] ?? 0);

    Capsule::table('mod_forward_sites')
        ->where('id', $siteId)
        ->update([
            'forward_site_id' => $remoteId > 0 ? $remoteId : null,
            'product_name' => $site['product_name'] ?: null,
            'server_id' => $userId !== null
                ? (is_array($service) ? (int) ($service['server_id'] ?? 0) : 0)
                : (int) ($data['server_id'] ?? $existing->server_id ?? 0),
            'service_id' => $userId !== null
                ? (is_array($service) ? (int) ($service['service_id'] ?? 0) : 0)
                : (int) ($data['service_id'] ?? $existing->service_id ?? 0),
            'domain' => $site['domain'],
            'listen_interface' => $site['listen_interface'],
            'listen_ip' => $site['listen_ip'],
            'backend_ip' => $site['backend_ip'],
            'backend_http_port' => $site['backend_http_port'],
            'backend_https_port' => $site['backend_https_port'],
            'tag' => $site['tag'],
            'transparent' => $site['transparent'] ? 1 : 0,
            'description' => $site['description'],
            'updated_at' => date('Y-m-d H:i:s'),
        ]);

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

    $enabled = $existing->status !== 'inactive';
    if (!empty($existing->forward_site_id)) {
        $api = forward_call_api('/api/sites/toggle?id=' . urlencode((string) $existing->forward_site_id), 'POST');
        if (!$api['success']) {
            return ['success' => false, 'message' => '后端切换站点状态失败：' . $api['message']];
        }
        if (isset($api['data']['enabled'])) {
            $enabled = (bool) $api['data']['enabled'];
        } else {
            $enabled = !$enabled;
        }
    } else {
        $enabled = !$enabled;
    }

    Capsule::table('mod_forward_sites')
        ->where('id', (int) $siteId)
        ->update([
            'status' => $enabled ? 'active' : 'inactive',
            'updated_at' => date('Y-m-d H:i:s'),
        ]);

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

    if (!empty($existing->forward_site_id)) {
        $api = forward_call_api('/api/sites?id=' . urlencode((string) $existing->forward_site_id), 'DELETE');
        if (!$api['success']) {
            $message = strtolower((string) $api['message']);
            if (strpos($message, 'not found') === false && strpos($message, '不存在') === false && strpos($message, 'site not found') === false) {
                return ['success' => false, 'message' => '后端删除站点失败：' . $api['message']];
            }
        }
    }

    Capsule::table('mod_forward_sites')->where('id', (int) $siteId)->delete();
    return ['success' => true, 'message' => '共享站点删除成功'];
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
    $services = forward_get_user_services($clientId, $allowedProducts, $allowedClientIps);
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
    forward_ensure_runtime_schema();

    forward_handle_admin_ajax();

    $settings = forward_get_module_settings();
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
    $serverIp = htmlspecialchars(forward_format_ip_list($allServerIps), ENT_QUOTES, 'UTF-8');
    $serverIpOptionsHtml = '';
    foreach ($allServerIps as $ip) {
        $escapedIp = htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
        $serverIpOptionsHtml .= '<option value="' . $escapedIp . '">' . $escapedIp . '</option>';
    }
    $apiEndpoint = htmlspecialchars((string) ($settings['api_endpoint'] ?? ''), ENT_QUOTES, 'UTF-8');
    $defaultTag = htmlspecialchars((string) ($settings['default_tag'] ?? ''), ENT_QUOTES, 'UTF-8');
    $inInterface = htmlspecialchars((string) ($settings['in_interface'] ?? ''), ENT_QUOTES, 'UTF-8');
    $outInterface = htmlspecialchars((string) ($settings['out_interface'] ?? ''), ENT_QUOTES, 'UTF-8');
    $csrfToken = htmlspecialchars(forward_get_csrf_token(), ENT_QUOTES, 'UTF-8');
    $csrfTokenJs = json_encode(forward_get_csrf_token(), JSON_UNESCAPED_UNICODE);
    $legacyServerMapNotice = forward_has_legacy_server_ip_product_map($settings)
        ? '检测到旧版按产品映射入口 IP 配置，它已不再参与宿主机匹配。请将 server_ip_product_map 手动迁移到新的 server_ip_server_map。'
        : '';

    echo <<<HTML
<style>
.forward-admin {
  --forward-ink: #17313a;
  --forward-muted: #60727a;
  --forward-line: #d5dee2;
  --forward-soft: #f4f7f8;
  --forward-hero-a: #17313a;
  --forward-hero-b: #2d5d63;
  --forward-accent: #efb366;
  --forward-card-shadow: 0 18px 40px rgba(16, 37, 43, 0.08);
  color: var(--forward-ink);
}
.forward-admin * {
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
  background: #fff;
  border: 1px solid var(--forward-line);
  border-radius: 18px;
  padding: 18px;
  box-shadow: var(--forward-card-shadow);
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
.forward-admin code {
  border-radius: 10px;
  padding: 2px 8px;
  background: var(--forward-soft);
  color: var(--forward-ink);
}
.forward-admin .table-responsive {
  border: 1px solid var(--forward-line);
  border-radius: 16px;
  overflow: hidden;
}
.forward-admin .table {
  margin: 0;
}
.forward-admin .table > thead > tr > th {
  border-top: 0;
  border-bottom: 1px solid var(--forward-line);
  background: var(--forward-soft);
  color: var(--forward-muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.forward-admin .table > tbody > tr > td {
  vertical-align: middle;
  border-top: 1px solid #ebeff1;
}
.forward-admin .table > tbody > tr:hover {
  background: #fbfcfc;
}
.forward-admin .btn {
  border-radius: 999px;
  font-weight: 600;
}
.forward-admin .btn-primary {
  background: linear-gradient(135deg, #1f5963, #3d7680);
  border-color: transparent;
}
.forward-admin .btn-warning {
  color: #17313a;
}
.forward-admin .label {
  display: inline-block;
  padding: 5px 10px;
  border-radius: 999px;
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
    echo '<div class="forward-admin__summary-card"><span>API 地址</span><strong>' . ($apiEndpoint !== '' ? $apiEndpoint : '-') . '</strong></div>';
    echo '<div class="forward-admin__summary-card"><span>默认标签</span><strong>' . ($defaultTag !== '' ? $defaultTag : '-') . '</strong></div>';
    echo '<div class="forward-admin__summary-card"><span>接口绑定</span><strong>入 ' . ($inInterface !== '' ? $inInterface : '-') . ' / 出 ' . ($outInterface !== '' ? $outInterface : '-') . '</strong></div>';
    echo '</div>';
    if ($legacyServerMapNotice !== '') {
        echo '<div class="alert alert-warning" style="border-radius:14px;margin-bottom:18px;">' . htmlspecialchars($legacyServerMapNotice, ENT_QUOTES, 'UTF-8') . '</div>';
    }

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
            echo '<tr>';
            echo '<td>' . (int) $rule['id'] . '</td>';
            echo '<td><strong>' . htmlspecialchars($rule['rule_name'], ENT_QUOTES, 'UTF-8') . '</strong><br><small>' . htmlspecialchars($rule['server_label'] ?: '-', ENT_QUOTES, 'UTF-8') . '</small></td>';
            echo '<td>' . htmlspecialchars($rule['in_ip'] . ':' . $rule['in_port'], ENT_QUOTES, 'UTF-8') . '</td>';
            echo '<td>' . htmlspecialchars($rule['out_ip'] . ':' . $rule['out_port'], ENT_QUOTES, 'UTF-8') . '</td>';
            echo '<td><span class="label label-info">' . htmlspecialchars($rule['protocol'], ENT_QUOTES, 'UTF-8') . '</span></td>';
            echo '<td>' . htmlspecialchars($rule['tag'] ?: '-', ENT_QUOTES, 'UTF-8') . '</td>';
            echo '<td><span class="label label-' . htmlspecialchars($rule['status_class'], ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($rule['status_text'], ENT_QUOTES, 'UTF-8') . '</span></td>';
            echo '<td>' . (int) $rule['user_id'] . '</td>';
            echo '<td><button type="button" class="btn btn-xs btn-' . ($rule['enabled'] ? 'default' : 'success') . ' forward-toggle-rule" data-id="' . (int) $rule['id'] . '">' . ($rule['enabled'] ? '禁用' : '启用') . '</button> ';
            echo '<button type="button" class="btn btn-xs btn-warning forward-edit-rule" data-rule="' . $ruleJson . '">编辑</button> ';
            echo '<button type="button" class="btn btn-xs btn-danger forward-delete-rule" data-id="' . (int) $rule['id'] . '">删除</button></td>';
            echo '</tr>';
        }
    } else {
        echo '<tr><td colspan="9" class="text-center text-muted">暂无规则</td></tr>';
    }

    echo '</tbody></table></div></div></div>';
    echo '<div class="modal fade" id="forwardAdminRuleModal" tabindex="-1" role="dialog" aria-hidden="true"><div class="modal-dialog" role="document"><div class="modal-content">';
    echo '<form id="forwardAdminRuleForm"><div class="modal-header"><button type="button" class="close" data-dismiss="modal"><span>&times;</span></button><h4 class="modal-title" id="forwardAdminRuleModalTitle">添加规则</h4></div>';
    echo '<div class="modal-body">';
    echo '<input type="hidden" name="rule_id" id="forward_admin_rule_id" value="">';
    echo '<input type="hidden" name="service_id" id="forward_admin_rule_service_id" value="0">';
    echo '<input type="hidden" name="server_id" id="forward_admin_rule_server_id" value="0">';
    echo '<input type="hidden" name="csrf_token" value="' . $csrfToken . '">';
    echo '<div class="form-group"><label for="forward_admin_rule_name">规则名称</label><input type="text" class="form-control" name="rule_name" id="forward_admin_rule_name" required></div>';
    echo '<div class="form-group"><label for="forward_admin_listen_ip">入口 IP</label><select class="form-control" name="listen_ip" id="forward_admin_listen_ip" required>' . $serverIpOptionsHtml . '</select></div>';
    echo '<div class="row"><div class="col-sm-6"><div class="form-group"><label for="forward_admin_internal_ip">目标 IP</label><input type="text" class="form-control" name="internal_ip" id="forward_admin_internal_ip" required></div></div>';
    echo '<div class="col-sm-6"><div class="form-group"><label for="forward_admin_internal_port">目标端口</label><input type="number" class="form-control" name="internal_port" id="forward_admin_internal_port" min="1" max="65535" required></div></div></div>';
    echo '<div class="row"><div class="col-sm-6"><div class="form-group"><label for="forward_admin_external_port">入口端口</label><input type="number" class="form-control" name="external_port" id="forward_admin_external_port" min="1" max="65535" required></div></div>';
    echo '<div class="col-sm-6"><div class="form-group"><label for="forward_admin_protocol">协议</label><select class="form-control" name="protocol" id="forward_admin_protocol" required>' . $protocolSelect . '</select></div></div></div>';
    echo '<div class="form-group"><label for="forward_admin_product_name">产品名称</label><input type="text" class="form-control" name="product_name" id="forward_admin_product_name"></div>';
    echo '<div class="form-group"><label for="forward_admin_description">描述</label><textarea class="form-control" name="description" id="forward_admin_description" rows="3"></textarea></div>';
    echo '<div class="alert alert-info" style="margin-bottom:0;">规则会写入 forward 的 <code>/api/rules</code>，入口 IP 可从当前配置的 IP 池中选择。</div>';
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
            echo '<tr>';
            echo '<td>' . (int) $site['id'] . '</td>';
            echo '<td><strong>' . htmlspecialchars($site['domain'], ENT_QUOTES, 'UTF-8') . '</strong><br><small>' . htmlspecialchars($site['server_label'] ?: '-', ENT_QUOTES, 'UTF-8') . '</small></td>';
            echo '<td>' . htmlspecialchars($site['listen_ip'], ENT_QUOTES, 'UTF-8') . ':80/443</td>';
            echo '<td>' . htmlspecialchars($site['backend_ip'], ENT_QUOTES, 'UTF-8') . ' <small>(' . htmlspecialchars($backendHttp . '，' . $backendHttps, ENT_QUOTES, 'UTF-8') . ')</small></td>';
            echo '<td>' . htmlspecialchars($site['tag'] ?: '-', ENT_QUOTES, 'UTF-8') . '</td>';
            echo '<td><span class="label label-' . htmlspecialchars($site['status_class'], ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($site['status_text'], ENT_QUOTES, 'UTF-8') . '</span></td>';
            echo '<td>' . (int) $site['user_id'] . '</td>';
            echo '<td><button type="button" class="btn btn-xs btn-' . ($site['enabled'] ? 'default' : 'success') . ' forward-toggle-site" data-id="' . (int) $site['id'] . '">' . ($site['enabled'] ? '禁用' : '启用') . '</button> ';
            echo '<button type="button" class="btn btn-xs btn-warning forward-edit-site" data-site="' . $siteJson . '">编辑</button> ';
            echo '<button type="button" class="btn btn-xs btn-danger forward-delete-site" data-id="' . (int) $site['id'] . '">删除</button></td>';
            echo '</tr>';
        }
    } else {
        echo '<tr><td colspan="8" class="text-center text-muted">暂无共享站点</td></tr>';
    }

    echo '</tbody></table></div></div></div>';
    echo '<div class="modal fade" id="forwardAdminSiteModal" tabindex="-1" role="dialog" aria-hidden="true"><div class="modal-dialog" role="document"><div class="modal-content">';
    echo '<form id="forwardAdminSiteForm"><div class="modal-header"><button type="button" class="close" data-dismiss="modal"><span>&times;</span></button><h4 class="modal-title" id="forwardAdminSiteModalTitle">添加共享站点</h4></div>';
    echo '<div class="modal-body">';
    echo '<input type="hidden" name="site_id" id="forward_admin_site_id" value="">';
    echo '<input type="hidden" name="service_id" id="forward_admin_site_service_id" value="0">';
    echo '<input type="hidden" name="server_id" id="forward_admin_site_server_id" value="0">';
    echo '<input type="hidden" name="csrf_token" value="' . $csrfToken . '">';
    echo '<div class="form-group"><label for="forward_admin_site_domain">域名</label><input type="text" class="form-control" name="domain" id="forward_admin_site_domain" placeholder="例如 app.example.com" required></div>';
    echo '<div class="form-group"><label for="forward_admin_site_listen_ip">入口 IP</label><select class="form-control" name="listen_ip" id="forward_admin_site_listen_ip" required>' . $serverIpOptionsHtml . '</select></div>';
    echo '<div class="row"><div class="col-sm-6"><div class="form-group"><label for="forward_admin_site_backend_ip">后端 IP</label><input type="text" class="form-control" name="backend_ip" id="forward_admin_site_backend_ip" required></div></div>';
    echo '<div class="col-sm-6"><div class="form-group"><label for="forward_admin_site_product_name">产品名称</label><input type="text" class="form-control" name="product_name" id="forward_admin_site_product_name"></div></div></div>';
    echo '<div class="row"><div class="col-sm-6"><div class="form-group"><label for="forward_admin_site_http_port">HTTP 端口</label><input type="number" class="form-control" name="backend_http_port" id="forward_admin_site_http_port" min="0" max="65535" value="80"></div></div>';
    echo '<div class="col-sm-6"><div class="form-group"><label for="forward_admin_site_https_port">HTTPS 端口</label><input type="number" class="form-control" name="backend_https_port" id="forward_admin_site_https_port" min="0" max="65535" value="443"></div></div></div>';
    echo '<div class="form-group"><label for="forward_admin_site_description">描述</label><textarea class="form-control" name="description" id="forward_admin_site_description" rows="3"></textarea></div>';
    echo '<div class="alert alert-info" style="margin-bottom:0;">站点会写入 forward 的 <code>/api/sites</code>，入口 IP 可从当前配置的 IP 池中选择，域名必须唯一。</div>';
    echo '</div><div class="modal-footer"><button type="button" class="btn btn-default" data-dismiss="modal">取消</button><button type="submit" class="btn btn-primary">保存</button></div></form>';
    echo '</div></div></div>';

    echo <<<HTML
<script>
(function ($) {
  var csrfToken = {$csrfTokenJs};

  function ensureSelectOption($select, value) {
    if (!value) {
      return;
    }
    if ($select.find('option[value="' + value.replace(/"/g, '\\"') + '"]').length) {
      return;
    }
    $('<option></option>').val(value).text(value + ' (当前值)').appendTo($select);
  }

  function resetForm() {
    $('#forwardAdminRuleForm')[0].reset();
    $('#forward_admin_rule_id').val('');
    $('#forward_admin_rule_service_id').val('0');
    $('#forward_admin_rule_server_id').val('0');
    $('#forwardAdminRuleModalTitle').text('添加规则');
    $('#forward_admin_listen_ip').prop('selectedIndex', 0);
  }

  function resetSiteForm() {
    $('#forwardAdminSiteForm')[0].reset();
    $('#forward_admin_site_id').val('');
    $('#forward_admin_site_service_id').val('0');
    $('#forward_admin_site_server_id').val('0');
    $('#forward_admin_site_http_port').val('80');
    $('#forward_admin_site_https_port').val('443');
    $('#forwardAdminSiteModalTitle').text('添加共享站点');
    $('#forward_admin_site_listen_ip').prop('selectedIndex', 0);
  }

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
    $('#forward_admin_rule_server_id').val(rule.server_id || 0);
    $('#forward_admin_rule_name').val(rule.rule_name || '');
    ensureSelectOption($('#forward_admin_listen_ip'), rule.in_ip || '');
    $('#forward_admin_listen_ip').val(rule.in_ip || '');
    $('#forward_admin_internal_ip').val(rule.out_ip || '');
    $('#forward_admin_internal_port').val(rule.out_port || '');
    $('#forward_admin_external_port').val(rule.in_port || '');
    $('#forward_admin_protocol').val(rule.protocol || 'tcp');
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
    $('#forward_admin_site_server_id').val(site.server_id || 0);
    $('#forward_admin_site_domain').val(site.domain || '');
    ensureSelectOption($('#forward_admin_site_listen_ip'), site.listen_ip || '');
    $('#forward_admin_site_listen_ip').val(site.listen_ip || '');
    $('#forward_admin_site_backend_ip').val(site.backend_ip || '');
    $('#forward_admin_site_http_port').val(site.backend_http_port || 0);
    $('#forward_admin_site_https_port').val(site.backend_https_port || 0);
    $('#forward_admin_site_product_name').val(site.product_name || '');
    $('#forward_admin_site_description').val(site.description || '');
    $('#forwardAdminSiteModal').modal('show');
  });

  $('.forward-delete-rule').on('click', function () {
    var ruleId = $(this).data('id');
    if (!confirm('确定删除这条规则吗？')) return;
    $.post(window.location.href, {action: 'delete_rule', rule_id: ruleId, csrf_token: csrfToken}, function (response) {
      if (response && response.success) {
        window.location.reload();
      } else {
        alert(response && response.message ? response.message : '删除失败');
      }
    }, 'json').fail(function () {
      alert('删除失败，请稍后重试');
    });
  });

  $('.forward-delete-site').on('click', function () {
    var siteId = $(this).data('id');
    if (!confirm('确定删除这个共享站点吗？')) return;
    $.post(window.location.href, {action: 'delete_site', site_id: siteId, csrf_token: csrfToken}, function (response) {
      if (response && response.success) {
        window.location.reload();
      } else {
        alert(response && response.message ? response.message : '删除失败');
      }
    }, 'json').fail(function () {
      alert('删除失败，请稍后重试');
    });
  });

  $('.forward-toggle-rule').on('click', function () {
    var ruleId = $(this).data('id');
    $.post(window.location.href, {action: 'toggle_rule', rule_id: ruleId, csrf_token: csrfToken}, function (response) {
      if (response && response.success) {
        window.location.reload();
      } else {
        alert(response && response.message ? response.message : '切换状态失败');
      }
    }, 'json').fail(function () {
      alert('切换状态失败，请稍后重试');
    });
  });

  $('.forward-toggle-site').on('click', function () {
    var siteId = $(this).data('id');
    $.post(window.location.href, {action: 'toggle_site', site_id: siteId, csrf_token: csrfToken}, function (response) {
      if (response && response.success) {
        window.location.reload();
      } else {
        alert(response && response.message ? response.message : '切换状态失败');
      }
    }, 'json').fail(function () {
      alert('切换状态失败，请稍后重试');
    });
  });

  $('#forwardAdminRuleForm').on('submit', function (e) {
    e.preventDefault();
    var formData = $(this).serializeArray();
    formData.push({name: 'action', value: $('#forward_admin_rule_id').val() ? 'edit_rule' : 'add_rule'});
    $.ajax({
      url: window.location.href,
      type: 'POST',
      data: $.param(formData),
      dataType: 'json'
    }).done(function (response) {
      if (response && response.success) {
        window.location.reload();
      } else {
        alert(response && response.message ? response.message : '保存失败');
      }
    }).fail(function () {
      alert('保存失败，请稍后重试');
    });
  });

  $('#forwardAdminSiteForm').on('submit', function (e) {
    e.preventDefault();
    var formData = $(this).serializeArray();
    formData.push({name: 'action', value: $('#forward_admin_site_id').val() ? 'edit_site' : 'add_site'});
    $.ajax({
      url: window.location.href,
      type: 'POST',
      data: $.param(formData),
      dataType: 'json'
    }).done(function (response) {
      if (response && response.success) {
        window.location.reload();
      } else {
        alert(response && response.message ? response.message : '保存失败');
      }
    }).fail(function () {
      alert('保存失败，请稍后重试');
    });
  });
})(jQuery);
</script>
HTML;

    echo '</div>';
    echo '</div>';
}

function forward_clientarea($vars)
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
    $services = $clientId > 0 ? forward_get_user_services($clientId, $allowedProducts, $allowedClientIps) : [];
    $services = forward_attach_service_listen_ips($services, $settings);
    $hasAccess = $clientId > 0 && !empty($services);
    $rules = $clientId > 0 ? forward_get_local_rules($clientId) : [];
    $sites = $clientId > 0 ? forward_get_local_sites($clientId) : [];
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
    $maxRules = max(0, (int) ($settings['max_rules_per_user'] ?? ($vars['max_rules_per_user'] ?? 10)));
    $maxSites = max(0, (int) ($settings['max_sites_per_user'] ?? ($vars['max_sites_per_user'] ?? 5)));
    $allServerIps = forward_get_all_server_ips($settings);

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
            'can_add_more' => $maxRules === 0 || count($rules) < $maxRules,
            'max_sites' => $maxSites,
            'current_site_count' => count($sites),
            'active_site_count' => $activeSiteCount,
            'inactive_site_count' => count($sites) - $activeSiteCount,
            'can_add_more_sites' => $maxSites === 0 || count($sites) < $maxSites,
            'service_ip_count' => forward_count_service_ips($services),
            'allowed_protocols' => $protocols,
            'server_ip' => $allServerIps[0] ?? '0.0.0.0',
            'server_ip_summary' => forward_format_ip_list($allServerIps),
            'server_ips' => $allServerIps,
        ],
    ];
}
