<?php
/**
 * WHMCS Forward addon hooks.
 */

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

if (!function_exists('forward_hooks_load_module')) {
    function forward_hooks_load_module()
    {
        if (!function_exists('forward_handle_service_lifecycle_hook')) {
            require_once __DIR__ . '/forward.php';
        }
    }
}

add_hook('AfterModuleSuspend', 1, function (array $vars) {
    forward_hooks_load_module();
    forward_handle_service_lifecycle_hook($vars, 'suspend');
});

add_hook('AfterModuleUnsuspend', 1, function (array $vars) {
    forward_hooks_load_module();
    forward_handle_service_lifecycle_hook($vars, 'unsuspend');
});

add_hook('AfterModuleTerminate', 1, function (array $vars) {
    forward_hooks_load_module();
    forward_handle_service_lifecycle_hook($vars, 'terminate');
});

add_hook('ServiceDelete', 1, function (array $vars) {
    forward_hooks_load_module();
    forward_handle_service_lifecycle_hook($vars, 'delete');
});
