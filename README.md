XtScript syntax parser
======================

About
-----

XtScript is a PHP-based syntax parser originally created for the XtGem mobile site building platform. It can also be used as a standalone library or as a reference implementation.

This source tree has been updated for modern PHP and hardened for running untrusted XtScript. The bundled `xtgem.php` remains only a standalone compatibility shim; a real XtGem/platform integration is expected to supply its own filesystem, content model and platform services.

Requirements
------------

- PHP 7+ syntax/runtime is supported by the codebase design.
- The hardened build is tested on PHP 8.4.16.
- The standalone example and tests also pass with `php -n`, so no optional PHP extension is required by the bundled implementation.

Run the example:

    php index.php

Security model
--------------

The interpreter now applies bounded execution to untrusted XtScript, including limits for source size, line count, commands, goto loops, recursion/execution depth, include count/depth/bytes, output size, request variables, variables, active call-frame variable memory and plugin calls.

Important security behavior:

- Native XtScript functions use an explicit allowlist. Public/internal PHP methods and magic methods cannot be reached by naming them from XtScript.
- Plugins are disabled by default. Enable only audited plugins, preferably per interpreter instance:

      $script->set_instance_allowed_plugins(array('cookie'));

- A plugin must explicitly expose callable methods:

      class xt_example
      {
          const XT_ALLOWED_METHODS = array('hello');
      }

- Plugins are arbitrary PHP and are denied inside cross-site/isolated execution by default. A plugin that is safe in that context must explicitly opt in:

      const XT_ALLOW_ISOLATED = true;

- Cross-site `include` requires an explicit `exportable` first-line directive. Imported functions keep origin/dependency provenance, so an imported site cannot inherit unrelated functions that only the caller imported.
- Cross-site code does not inherit caller request variables and cannot call another origin's internal helper functions.
- File access is canonicalized, root-bounded, size-bounded and blocks sensitive/hidden paths and executable/config key extensions. File reads are revalidated after opening to narrow filesystem race windows.
- The standalone filesystem rejects traversal using both `/` and `\`, including percent-decoded traversal.
- Debug functions are disabled by default.
- The cookie plugin is allowlisted, host-bound, unavailable in isolated cross-site execution, and stores logical XtScript cookies in a deterministic per-domain physical namespace. This prevents `cookie::get` from reading arbitrary platform/session cookies by name.

Raw HTML output
---------------

`print` and `print_raw` retain legacy XtScript output semantics and are not automatic HTML-escaping boundaries. Do not render untrusted values into a privileged management/admin origin without escaping them. Use `htmlspecialchars` when output must be HTML-safe.

Host trust boundaries
---------------------

The interpreter cannot make arbitrary host code safe. In a real integration, audit these separately:

- the implementation returned by `X::model('filesystem')`;
- `content_model::parse_xt()`;
- every enabled plugin;
- platform code that constructs `$url`, `$info` and initial variables;
- filesystem permissions. The plugin/code directory must not be tenant-writable.

Plugins that perform network, database, filesystem or process operations should be treated as trusted server-side code even when their XtScript method list is small.

Testing
-------

Run all bundled verification with PHP's normal configuration:

    php tests/security_regression.php
    php tests/fuzz.php
    php tests/plugin_hijack.php
    php tests/cookie_roundtrip.php

For a stricter portability run without `php.ini`/optional extensions:

    php -n tests/security_regression.php
    php -n tests/fuzz.php
    php -n tests/plugin_hijack.php
    php -n tests/cookie_roundtrip.php

The security regression covers traversal, symlink targets, cross-origin function/helper isolation, caller capability leakage, request-variable isolation, plugin isolation, plugin class hijacking, cookie namespace isolation, recursive/goto/variable-memory limits and standalone URL/path parsing.

Files
-----

- `script.php` - XtScript interpreter.
- `xtgem.php` - standalone compatibility shim.
- `xtscript_plugins/xt_cookie.php` - hardened example cookie plugin.
- `index.php` - standalone example runner.
- `examples.txt`, `includes.xt` - example XtScript content.
- `tests/` - regression, fuzz and security boundary tests.

License
-------

The original source is MIT licensed.

Original author
---------------

Arminas Žukauskas < arminas ( at ) xtgem ( dot ) com >
