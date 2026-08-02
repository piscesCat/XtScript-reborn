<?php

error_reporting(E_ALL);
set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    throw new ErrorException($message, 0, $severity, $file, $line);
});

$root = dirname(__DIR__);
require_once $root . '/xtgem.php';
require_once $root . '/script.php';

$vars = array();
$info = array();
$functions = array();
$script = new script('test.xtgem.com/index', $info, $vars, $functions);
$script->set_instance_allowed_plugins(array('cookie'));

$output = $script->eval_syntax(
    "call cookie::set \$name=foo;\$val=bar;\$force_current=1\n" .
    "call cookie::get \$name=foo;\$default=no",
    1
);

$expectedName = 'xts_' . substr(hash('sha256', 'test.xtgem.com'), 0, 16) . '_foo';
if ($output !== 'bar' || !isset($_COOKIE[$expectedName]) || $_COOKIE[$expectedName] !== 'bar') {
    fwrite(STDERR, "FAIL cookie roundtrip\n");
    exit(1);
}

if (isset($_COOKIE['foo'])) {
    fwrite(STDERR, "FAIL logical cookie leaked into raw namespace\n");
    exit(1);
}

echo "PASS namespaced cookie roundtrip\n";
