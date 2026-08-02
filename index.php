<?php

$DIR = __DIR__;

require_once $DIR . '/xtgem.php';
require_once $DIR . '/script.php';

$contents = @file_get_contents($DIR . '/examples.txt');
if ($contents === false) {
    http_response_code(500);
    die('Unable to load examples.');
}

$url = 'test.xtgem.com/index';
$info = array();
$url_vars = array();
$script = new script($url, $info, $url_vars);
$script->set_instance_allowed_plugins(array('cookie'));
$version = 1;

try {
    // Callback replacements are literal, so XtScript output containing $1 or
    // backslashes cannot be reinterpreted as preg_replace backreferences.
    $contents = preg_replace_callback(
        '#<!--parser:xtscript-->(.*?)<!--/parser:xtscript-->#mis',
        static function ($match) use ($script, $version) {
            return $script->eval_syntax($match[1], $version);
        },
        $contents
    );

    if ($contents === null) {
        throw new RuntimeException('Parser block replacement failed.');
    }
} catch (SyntaxException $e) {
    die($e->errorMessage($script, $e));
} catch (Throwable $e) {
    http_response_code(500);
    die('XtScript Error.');
}

die($contents);
