<?php

error_reporting(E_ALL);
set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    throw new ErrorException($message, 0, $severity, $file, $line);
});

// Simulate a class-name collision loaded from an unrelated file before the
// real plugin. script.php must refuse it instead of dispatching to it.
class xt_cookie
{
    const XT_ALLOWED_METHODS = array('get');
    public static function get($args)
    {
        return 'HIJACK';
    }
}

$root = dirname(__DIR__);
require_once $root . '/xtgem.php';
require_once $root . '/script.php';

$vars = array();
$info = array();
$functions = array();
$script = new script('test.xtgem.com/index', $info, $vars, $functions);
$script->set_instance_allowed_plugins(array('cookie'));
$output = $script->eval_syntax('call cookie::get $name=x', 1);

if (strpos($output, 'Undefined plugin `cookie`') === false) {
    fwrite(STDERR, "FAIL plugin class hijack was not blocked: {$output}\n");
    exit(1);
}

echo "PASS plugin class hijack blocked\n";
