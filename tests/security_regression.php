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

script::set_allowed_plugins(array());

$passed = 0;
$failed = 0;

function contains_text($haystack, $needle)
{
    return strpos((string) $haystack, (string) $needle) !== false;
}

function ends_with_text($haystack, $needle)
{
    $haystack = (string) $haystack;
    $needle = (string) $needle;
    return $needle === '' || substr($haystack, -strlen($needle)) === $needle;
}

function check_case($name, $ok, $detail = '')
{
    global $passed, $failed;
    if ($ok) {
        ++$passed;
        echo "PASS {$name}\n";
        return;
    }

    ++$failed;
    echo "FAIL {$name}" . ($detail !== '' ? ': ' . $detail : '') . "\n";
}

function run_xt($source, $url = 'test.xtgem.com/index', $vars = array(), $plugins = array())
{
    $info = array();
    $functions = array();
    $script = new script($url, $info, $vars, $functions);
    $script->set_instance_allowed_plugins($plugins);
    return array($script->eval_syntax($source, 1), $vars, $script->get_syntax_functions());
}

$siteRoot = $root . '/sites';
$bRoot = $siteRoot . '/b.example';
$cRoot = $siteRoot . '/c.example';

try {
    list($out) = run_xt("assign \$x = 2\nassign \$y = 3\nprint (\$x+\$y*4)");
    check_case('math precedence', $out === '14', $out);

    list($out) = run_xt("if 1 == 1\nprint yes\nelse\nprint no\nendif");
    check_case('if branch', $out === 'yes', $out);

    list($out) = run_xt("function f \$a=0\nreturn \$a\nendfunction\ncall f \$a=7");
    check_case('function call', $out === '7', $out);

    list($out) = run_xt("print \$missing");
    check_case('missing variable is empty', $out === '', $out);

    list($out) = run_xt('print_raw $1\\1');
    check_case('raw dollar/backslash preserved', $out === '$1\\1', $out);

    list($out) = run_xt("call file_get_contents \$file=script.php");
    check_case('sensitive php read blocked', $out === '', $out);

    list($out) = run_xt("call file_get_contents \$file=../script.php");
    check_case('file traversal blocked', $out === '', $out);

    list($out) = run_xt("call cookie::get \$name=x");
    check_case('plugin disabled by default', contains_text($out, 'not enabled'), $out);

    list($out) = run_xt('call construct');
    check_case('magic constructor not callable', contains_text($out, 'Undefined function'), $out);

    @mkdir($bRoot, 0777, true);
    @mkdir($cRoot, 0777, true);

    file_put_contents($bRoot . '/helper.xt', "function helper\nprint BSECRET\nendfunction\n");
    file_put_contents(
        $bRoot . '/export.xt',
        "#exportable\ninclude helper.xt\nfunction own\ncall @helper\nendfunction\n" .
        "function steal\ncall c.example@@secret\nendfunction\n" .
        "function stealpublic\ncall c.example@public\nendfunction\n"
    );
    file_put_contents($cRoot . '/helper.xt', "function secret\nprint CSECRET\nendfunction\n");
    file_put_contents($cRoot . '/export.xt', "#exportable\ninclude helper.xt\nfunction public\nprint COK\nendfunction\n");

    list($out) = run_xt("include b.example/export.xt\ninclude c.example/export.xt\ncall b.example@own");
    check_case('own internal helper callable', $out === 'BSECRET', $out);

    list($out) = run_xt("include b.example/export.xt\ninclude c.example/export.xt\ncall b.example@steal");
    check_case('cross-origin internal helper blocked', contains_text($out, 'Undefined function'), $out);

    list($out) = run_xt("include b.example/export.xt\ninclude c.example/export.xt\ncall b.example@stealpublic");
    check_case('caller imports not inherited by isolated code', contains_text($out, 'Undefined function'), $out);

    list($out) = run_xt("include b.example/export.xt\ncall b.example@@helper");
    check_case('caller cannot call imported internal helper', contains_text($out, 'Undefined function'), $out);

    file_put_contents(
        $bRoot . '/withdep.xt',
        "#exportable\ninclude c.example/export.xt\nfunction usec\ncall c.example@public\nendfunction\n"
    );
    list($out) = run_xt("include b.example/withdep.xt\ncall b.example@usec");
    check_case('explicit nested dependency callable', $out === 'COK', $out);

    file_put_contents($cRoot . '/private.xt', "# not exportable\nfunction leak\nprint LEAK\nendfunction\n");
    list($out) = run_xt("include c.example/private.xt\ncall c.example@leak");
    check_case('non-exportable cross-site file blocked', contains_text($out, 'Undefined function'), $out);

    @symlink($root . '/script.php', $bRoot . '/link.xt');
    list($out) = run_xt("include b.example/link.xt\nprint ok");
    check_case('symlink-to-php include blocked', $out === 'ok', $out);

    $_GET = array('secret' => 'A_REQUEST');
    $_POST = array();
    file_put_contents($bRoot . '/request.xt', "#exportable\nfunction readreq\nget secret\nprint \$secret\nendfunction\n");
    list($out) = run_xt("include b.example/request.xt\ncall b.example@readreq");
    check_case('cross-site request vars isolated', $out === '', $out);
    $_GET = array();
    $_POST = array();

    file_put_contents(
        $bRoot . '/cookie.xt',
        "#exportable\nfunction readcookie\ncall cookie::get \$name=foo;\$default=none\nendfunction\n"
    );
    $_COOKIE = array('foo' => 'A_COOKIE');
    list($out) = run_xt(
        "include b.example/cookie.xt\ncall b.example@readcookie",
        'test.xtgem.com/index',
        array(),
        array('cookie')
    );
    check_case('plugin blocked in isolated execution', contains_text($out, 'not available in isolated execution'), $out);
    $_COOKIE = array();

    $_SERVER['HTTP_HOST'] = 'other.example';
    $_COOKIE = array('foo' => 'A_COOKIE');
    list($out) = run_xt("call cookie::get \$name=foo;\$default=none", 'test.xtgem.com/index', array(), array('cookie'));
    check_case('cookie host mismatch blocked', $out === '', $out);
    unset($_SERVER['HTTP_HOST']);
    $_COOKIE = array();

    $_COOKIE = array('foo' => 'PLATFORM_SECRET', 'PHPSESSID' => 'PLATFORM_SESSION');
    list($out) = run_xt("call cookie::get \$name=foo;\$default=none", 'test.xtgem.com/index', array(), array('cookie'));
    check_case('platform cookie namespace isolated', $out === 'none', $out);

    $physicalCookie = 'xts_' . substr(hash('sha256', 'test.xtgem.com'), 0, 16) . '_foo';
    $_COOKIE = array($physicalCookie => 'bar');
    list($out) = run_xt("call cookie::get \$name=foo;\$default=none", 'test.xtgem.com/index', array(), array('cookie'));
    check_case('namespaced cookie readable by logical name', $out === 'bar', $out);
    $_COOKIE = array();

    list($out) = run_xt("call cookie::get \$name=foo;\$default=none", 'test.xtgem.com/index', array(), array('cookie'));
    check_case('cookie plugin enabled explicitly', $out === 'none', $out);

    list($out) = run_xt("call cookie::set \$name=bad name;\$val=x", 'test.xtgem.com/index', array(), array('cookie'));
    check_case('malformed cookie input contained', $out === '', $out);

    list($out) = run_xt('call cookie::__setup', 'test.xtgem.com/index', array(), array('cookie'));
    check_case('plugin setup not exposed', contains_text($out, 'not exposed'), $out);

    list($out) = run_xt(str_repeat("print x\n", 50010));
    check_case(
        'source/command budget enforced',
        contains_text($out, 'limit') || contains_text($out, 'size') || contains_text($out, 'count'),
        substr($out, 0, 100)
    );

    list($out) = run_xt("call str_repeat \$val=x;\$multiplier=999999999");
    check_case('repeat memory bomb blocked', $out === '', $out);

    $largeVars = array();
    for ($i = 0; $i < 4; ++$i) {
        $largeVars['v' . $i] = str_repeat('x', 900000);
    }
    list($out) = run_xt("function rec\ncall rec\nendfunction\ncall rec", 'test.xtgem.com/index', $largeVars);
    check_case('aggregate call-frame variable memory bounded', contains_text($out, 'Active variable memory limit'), $out);

    list($out) = run_xt("@loop\ngoto @loop");
    check_case('goto loop bounded', contains_text($out, 'goto limit') || contains_text($out, 'command limit'), $out);

    list($out) = run_xt("function rec\ncall rec\nendfunction\ncall rec");
    check_case('recursive function bounded', contains_text($out, 'nesting level') || contains_text($out, 'memory limit'), $out);

    $_GET = array('x' => 'get');
    $_POST = array('x' => 'post');
    $localRequestFile = $root . '/request_local_test.xt';
    file_put_contents($localRequestFile, "get x\nprint \$x\n");
    list($out) = run_xt("include request_local_test.xt");
    @unlink($localRequestFile);
    check_case('POST overrides GET without array_merge copy', $out === 'post', $out);
    $_GET = array();
    $_POST = array();

    $domain = common::domain('test.xtgem.com/index?x=1');
    check_case(
        'domain parser',
        is_array($domain)
            && $domain[1] === 'test.xtgem.com'
            && $domain[4] === '/index'
            && $domain[5] === '?x=1',
        var_export($domain, true)
    );

    $fs = new filesystem();
    check_case('relative xt stays local', $fs->path('includes.xt') === false, var_export($fs->path('includes.xt'), true));

    $path = $fs->path('test.xtgem.com/index');
    check_case(
        'demo path maps inside project',
        is_array($path) && ends_with_text(str_replace('\\', '/', $path['absolute']), '/XtScript-master/index'),
        var_export($path, true)
    );

    check_case(
        'encoded slash traversal rejected',
        $fs->path('test.xtgem.com/%2e%2e/script.php') === false,
        var_export($fs->path('test.xtgem.com/%2e%2e/script.php'), true)
    );

    check_case(
        'encoded backslash traversal rejected',
        $fs->path('test.xtgem.com/%5c..%5cscript.php') === false,
        var_export($fs->path('test.xtgem.com/%5c..%5cscript.php'), true)
    );

    check_case('userinfo host rejected', $fs->path('evil@test.xtgem.com/index') === false);
    check_case('port-bearing host rejected by standalone shim', $fs->path('test.xtgem.com:80/index') === false);
} finally {
    $_GET = array();
    $_POST = array();
    $_COOKIE = array();
    unset($_SERVER['HTTP_HOST']);

    foreach (array($bRoot, $cRoot) as $dir) {
        if (is_dir($dir)) {
            foreach (glob($dir . '/*') ?: array() as $file) {
                @unlink($file);
            }
            @rmdir($dir);
        }
    }
    @rmdir($siteRoot);
}

echo "RESULT {$passed} pass {$failed} fail\n";
exit($failed > 0 ? 1 : 0);
