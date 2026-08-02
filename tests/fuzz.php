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

function fuzz_run($source)
{
    $vars = array();
    $info = array();
    $functions = array();
    $script = new script('test.xtgem.com/index', $info, $vars, $functions);
    return $script->eval_syntax($source, 1);
}

$source = file_get_contents($root . '/script.php');
preg_match_all('/private function __([A-Za-z0-9_]+)\s*\(/', $source, $matches);
$nativeNames = array_values(array_unique($matches[1]));
$failures = array();
$cases = 0;

foreach ($nativeNames as $name) {
    $inputs = array(
        'call ' . $name,
        'call ' . $name . ' $val=abc;$num=-2;$min=9;$max=1;$haystack=abc;$needle=;' .
            '$start=-999999;$length=-999999;$multiplier=999999999;$pad_length=999999999',
    );

    foreach ($inputs as $input) {
        ++$cases;
        try {
            fuzz_run($input);
        } catch (Throwable $e) {
            $failures[] = $name . ': ' . get_class($e) . ': ' . $e->getMessage();
        }
    }
}

$commands = array(
    'assign', 'var', 'delete', 'del', 'get', 'get_or_default', 'print', 'print_raw',
    'call', 'if', 'elseif', 'else', 'endif', 'goto', 'function', 'endfunction',
    'return', 'include', 'nonsense'
);
$alphabet = "abcXYZ0123_$@()=;<>!+-*/% .:/\\\n";

for ($i = 0; $i < 3000; ++$i) {
    $lines = array();
    $lineCount = random_int(1, 12);

    for ($line = 0; $line < $lineCount; ++$line) {
        $command = $commands[array_rand($commands)];
        $length = random_int(0, 80);
        $rest = '';
        for ($j = 0; $j < $length; ++$j) {
            $rest .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        $lines[] = $command . ' ' . $rest;
    }

    ++$cases;
    try {
        fuzz_run(implode("\n", $lines));
    } catch (Throwable $e) {
        $failures[] = 'fuzz#' . $i . ': ' . get_class($e) . ': ' . $e->getMessage();
        if (count($failures) > 20) {
            break;
        }
    }
}

echo 'NATIVE_METHODS=' . count($nativeNames) . "\n";
echo 'CASES=' . $cases . "\n";
echo 'FAIL=' . count($failures) . "\n";
foreach ($failures as $failure) {
    echo $failure . "\n";
}

exit($failures ? 1 : 0);
