<?php
namespace WHMCS\Database {
    class Capsule {
        public static $rows = [];
        public static $writes = 0;
        public static function table($name) { return new Query($name); }
    }
    class Query {
        private $table;
        private $filters = [];
        public function __construct($name) { $this->table = $name; }
        public function where($key, $value) { $this->filters[$key] = $value; return $this; }
        public function get() {
            return array_values(array_filter(Capsule::$rows[$this->table] ?? [], function ($row) {
                foreach ($this->filters as $key => $value) {
                    if (($row->$key ?? null) != $value) { return false; }
                }
                return true;
            }));
        }
        public function first() { return $this->get()[0] ?? null; }
        public function update($values) { Capsule::$writes++; return 1; }
        public function insert($values) { Capsule::$writes++; return true; }
    }
}
namespace {
    define('WHMCS', true);
    require __DIR__ . '/../whmcs/forward/forward.php';
    use WHMCS\Database\Capsule;
    function check($condition, $message) {
        if (!$condition) { throw new \RuntimeException($message); }
    }
    $service = ['server_id' => 1, 'service_id' => 100, 'user_id' => 10, 'ips' => ['192.0.2.10']];
    check(forward_remote_enabled_path('/api/rules/toggle', 7, false) === '/api/rules/enabled?id=7&enabled=false', 'rule lifecycle uses toggle');
    check(forward_remote_enabled_path('/api/sites/toggle', 7, true) === '/api/sites/enabled?id=7&enabled=true', 'site lifecycle uses toggle');
    check(forward_remote_enabled_path('/unsupported', 7, true) === '', 'unknown state endpoint accepted');
    foreach ([['rules', 'rule', 'forward_upsert_synced_rule'], ['sites', 'site', 'forward_upsert_synced_site']] as $case) {
        list($plural, $singular, $upsert) = $case;
        $table = 'mod_forward_' . $plural;
        $remote = 'remote_' . $singular . '_id';
        $legacy = 'forward_' . $singular . '_id';
        $resource = ['id' => 7, 'in_ip' => '192.0.2.1', 'out_ip' => '192.0.2.10', 'protocol' => 'tcp',
            'in_port' => 20022, 'out_port' => 22, 'backend_ip' => '192.0.2.10', 'domain' => 'example.test'];
        Capsule::$rows = [];
        Capsule::$writes = 0;
        check(!$upsert($resource, $service), 'unmarked remote resource adopted by IP');
        check(!$upsert($resource, $service, true), 'admin import assigned unmarked resource to a client');
        check(Capsule::$writes === 0, 'unauthorized insert');
        $owner = (object) ['id' => 1, $remote => 7, 'server_id' => 1, 'service_id' => 200, 'user_id' => 20];
        Capsule::$rows[$table] = [$owner];
        check(!$upsert($resource, $service), 'resource ownership reassigned');
        check(Capsule::$writes === 0, 'unauthorized update');
        check(forward_trusted_sync_services([$service], $table, $remote, $legacy) === [], 'untrusted mapping selected');
        $owner->service_id = 100; $owner->user_id = 10;
        $trusted = forward_trusted_sync_services([$service], $table, $remote, $legacy);
        check(($trusted[7]['service_id'] ?? 0) === 100, 'trusted mapping not selected');
        check($upsert($resource, $service), 'trusted resource failed to synchronize');
        Capsule::$rows[$table][] = clone $owner;
        $trusted = forward_trusted_sync_services([$service], $table, $remote, $legacy);
        check(array_key_exists(7, $trusted) && $trusted[7] === null, 'duplicate mapping not rejected');
        Capsule::$rows[$table] = [];
        check($upsert($resource, ['server_id' => 1, 'service_id' => 0, 'user_id' => 0], true), 'explicit unbound import rejected');
    }
    echo "WHMCS ownership behavior tests passed\n";
}
