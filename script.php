<?php

declare(strict_types=0);

register_shutdown_function('HandleXtScriptShutdown');

function HandleXtScriptShutdown()
{
    $error = error_get_last();

    if (!$error) {
        return;
    }

    $fatalTypes = array(E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE);

    if (
        in_array($error['type'], $fatalTypes, true)
        && stripos((string) $error['message'], 'Maximum function nesting level') !== false
    ) {
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }

        if (class_exists('common') && class_exists('X')) {
            common::error_page('Maximum function nesting level reached', X::get('user_site'));
        }
    }
}

class script
{
    const XT_SYNTAX_NONE = 0;
    const XT_SYNTAX_FUNCTION = 1;
    const XT_SYNTAX_FUNCTION_IGNORE = 2;
    const XT_SYNTAX_IF_TRUE = 3;
    const XT_SYNTAX_IF_FALSE = 4;
    const XT_SYNTAX_IF_FALSE_ELSE = 5;
    const XT_SYNTAX_IF_SKIP = 6;

    // Execution and memory budgets for untrusted XtScript.
    const XT_SYNTAX_TIMEOUT = 4;
    const XT_SYNTAX_MAX_FUNCTION_DEPTH = 16;
    const XT_SYNTAX_MAX_EXECUTION_DEPTH = 32;
    const XT_SYNTAX_MAX_COMMANDS = 50000;
    const XT_SYNTAX_MAX_LINES = 50000;
    const XT_SYNTAX_MAX_TOTAL_COMMANDS = 50000;
    const XT_SYNTAX_MAX_GOTO = 2000;
    const XT_SYNTAX_MAX_SOURCE_BYTES = 1048576;
    const XT_SYNTAX_MAX_LINE_BYTES = 65536;
    const XT_SYNTAX_MAX_VALUE_BYTES = 1048576;
    const XT_SYNTAX_MAX_OUTPUT_BYTES = 4194304;
    const XT_SYNTAX_MAX_INCLUDE_DEPTH = 16;
    const XT_SYNTAX_MAX_INCLUDE_FILES = 64;
    const XT_SYNTAX_MAX_INCLUDE_FILE_BYTES = 1048576;
    const XT_SYNTAX_MAX_INCLUDE_TOTAL_BYTES = 4194304;
    const XT_SYNTAX_MAX_PLUGIN_CALLS = 256;
    const XT_SYNTAX_MAX_FUNCTIONS = 1024;
    const XT_SYNTAX_MAX_REQUEST_VARS = 256;
    const XT_SYNTAX_MAX_REQUEST_VALUE_BYTES = 65536;
    const XT_SYNTAX_MAX_REQUEST_TOTAL_BYTES = 2097152;
    const XT_SYNTAX_MAX_VARIABLES = 2048;
    const XT_SYNTAX_MAX_VARIABLE_BYTES = 8388608;
    const XT_SYNTAX_MAX_ACTIVE_VARIABLE_BYTES = 16777216;
    const XT_SYNTAX_MAX_VARIABLE_NAME_BYTES = 256;
    const XT_SYNTAX_MAX_FUNCTION_ARGS = 256;

    private $url = false;
    private $vars = array();
    private $info = false;
    private $version = 1;

    private $cmd_list = array();
    private $program_counter = 0;
    private $executed_commands = 0;
    private $goto_count = 0;
    private $output_bytes = 0;
    private $variable_bytes = 0;
    private $setup_error = null;
    private $runtime_variable_registered = false;
    private $request_vars_allowed = true;
    private $isolated_execution = false;
    private $runtime_context;
    private $allowed_plugins_override = null;
    private $debug_functions_enabled_override = null;

    private $xt_syntax_state = array(self::XT_SYNTAX_NONE);
    private $xt_syntax_functions = array();
    private $xt_syntax_indexes = array();
    private $active_function = null;

    private $xt_syntax_plugins_directory = './xtscript_plugins';
    private $xt_syntax_plugins = array();

    private static $allowed_plugins = array();
    private static $debug_functions_enabled = false;

    public function __construct($url = false, $info = false, &$vars = false, &$syntax_functions = false)
    {
        $this->runtime_context = $this->new_runtime_context();

        if ($url !== false && $info !== false && $vars !== false) {
            $this->setup($url, $info, $vars, $syntax_functions);
        }

        $directory = $this->xt_syntax_plugins_directory;

        if ($directory === '' || $directory[0] !== '/') {
            $resolved = realpath(dirname(__FILE__) . '/' . $directory);
            if ($resolved !== false) {
                $directory = $resolved;
            } else {
                $directory = dirname(__FILE__) . '/' . trim($directory, '/');
            }
        }

        $this->xt_syntax_plugins_directory = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR;
    }

    private function new_runtime_context()
    {
        return (object) array(
            'started' => null,
            'execution_depth' => 0,
            'function_depth' => 0,
            'total_commands' => 0,
            'include_depth' => 0,
            'include_files' => 0,
            'include_bytes' => 0,
            'plugin_calls' => 0,
            'active_variable_bytes' => 0
        );
    }

    public function setup($url, $info, &$vars, &$syntax_functions = false)
    {
        $this->vars = &$vars;
        $this->url = $url;
        $this->info = $info;

        $this->cmd_list = array();
        $this->program_counter = 0;
        $this->executed_commands = 0;
        $this->goto_count = 0;
        $this->output_bytes = 0;
        $this->variable_bytes = 0;
        $this->setup_error = null;
        $this->runtime_variable_registered = false;
        $this->xt_syntax_indexes = array();
        $this->active_function = null;

        if ($syntax_functions !== false) {
            $this->xt_syntax_functions = &$syntax_functions;
        } else {
            $this->xt_syntax_functions = array();
        }

        $this->xt_syntax_state = array(self::XT_SYNTAX_NONE);
        $this->refresh_variable_budget();
    }

    public function get_syntax_functions()
    {
        return $this->xt_syntax_functions;
    }

    public function get_command_list()
    {
        return $this->cmd_list;
    }

    public function get_program_counter()
    {
        return $this->program_counter;
    }


    // Host-only security configuration. XtScript itself cannot call these public PHP methods.
    public static function set_allowed_plugins($plugins)
    {
        self::$allowed_plugins = self::normalize_plugin_list($plugins);
    }

    public static function set_debug_functions_enabled($enabled)
    {
        self::$debug_functions_enabled = (bool) $enabled;
    }

    // Prefer these instance-scoped setters in long-running multi-tenant PHP servers.
    public function set_instance_allowed_plugins($plugins)
    {
        $this->allowed_plugins_override = self::normalize_plugin_list($plugins);
    }

    public function set_instance_debug_functions_enabled($enabled)
    {
        $this->debug_functions_enabled_override = (bool) $enabled;
    }

    private static function normalize_plugin_list($plugins)
    {
        $allowed = array();
        if (is_array($plugins)) {
            foreach ($plugins as $plugin) {
                $plugin = (string) $plugin;
                if (preg_match('#^[A-Za-z_][A-Za-z0-9_]*$#', $plugin) === 1) {
                    $allowed[$plugin] = true;
                }
            }
        }
        return $allowed;
    }

    public function eval_syntax($str, $version)
    {
        $ctx = $this->runtime_context;
        $isRootExecution = $ctx->execution_depth === 0;

        if ($ctx->execution_depth >= self::XT_SYNTAX_MAX_EXECUTION_DEPTH) {
            return 'XtScript Error: Maximum execution depth reached.';
        }

        if ($isRootExecution) {
            $ctx->started = microtime(true);
            $ctx->function_depth = 0;
            $ctx->total_commands = 0;
            $ctx->include_depth = 0;
            $ctx->include_files = 0;
            $ctx->include_bytes = 0;
            $ctx->plugin_calls = 0;
            $ctx->active_variable_bytes = 0;
        }

        ++$ctx->execution_depth;

        try {
            $this->refresh_variable_budget();
            if ($this->setup_error !== null) {
                return $this->setup_error;
            }

            if ($ctx->active_variable_bytes + $this->variable_bytes > self::XT_SYNTAX_MAX_ACTIVE_VARIABLE_BYTES) {
                return 'XtScript Error: Active variable memory limit exceeded.';
            }
            $ctx->active_variable_bytes += $this->variable_bytes;
            $this->runtime_variable_registered = true;

            $this->version = (int) $version;

            if ($this->version !== 1) {
                return '';
            }

            $str = (string) $str;
            if (strlen($str) > self::XT_SYNTAX_MAX_SOURCE_BYTES) {
                return 'XtScript Error: Source size limit exceeded.';
            }

            $str = str_replace(array("\r\n", "\r"), "\n", $str);

            // Remove block comments, including empty comments.
            $str = preg_replace('#/\\*.*?\\*/#s', '', $str);

            // Merge multiline {{ ... }} strings without repeatedly scanning/replacing the full source.
            $str = preg_replace_callback(
                '#\\{\\{(.*?)\\}\\}#s',
                static function ($matches) {
                    return str_replace("\n", '\\n', $matches[1]);
                },
                $str
            );

            $lineCount = substr_count($str, "\n") + 1;
            if ($lineCount > self::XT_SYNTAX_MAX_LINES) {
                return 'XtScript Error: Maximum line count reached.';
            }

            $this->cmd_list = explode("\n", $str);
            if (count($this->cmd_list) === 1) {
                $brCount = substr_count($str, '[br]') + 1;
                if ($brCount > self::XT_SYNTAX_MAX_LINES) {
                    return 'XtScript Error: Maximum line count reached.';
                }
                $this->cmd_list = explode('[br]', $str);
            }

            $this->build_indexes();
            $this->program_counter = 0;
            $this->executed_commands = 0;
            $this->goto_count = 0;
            $this->output_bytes = 0;

            $result = array();
            $count = count($this->cmd_list);

            while ($this->program_counter < $count) {
                if ($this->has_timed_out()) {
                    return 'XtScript Error: Timeout.';
                }

                if (++$this->executed_commands > self::XT_SYNTAX_MAX_COMMANDS) {
                    return 'XtScript Error: Maximum command limit reached.';
                }

                if (++$ctx->total_commands > self::XT_SYNTAX_MAX_TOTAL_COMMANDS) {
                    return 'XtScript Error: Global command limit reached.';
                }

                $currentIndex = $this->program_counter;
                $rawLine = $this->cmd_list[$currentIndex];
                ++$this->program_counter;

                if (strlen($rawLine) > self::XT_SYNTAX_MAX_LINE_BYTES) {
                    return 'XtScript Error: Line size limit exceeded.';
                }

                $line = trim(trim($rawLine), ';');

                if ($line === '' || $line[0] === '#') {
                    continue;
                }

                // Labels are no-op commands.
                if ($line[0] === '@') {
                    continue;
                }

                $line = str_replace('\\n', "\n", $line);
                list($cmd, $args) = $this->parse_command($line);

                try {
                    $value = $this->eval_cmd($cmd, $args, $rawLine);
                } catch (Throwable $e) {
                    return 'XtScript Error: Runtime failure on line ' . ($currentIndex + 1) . '.';
                }

                if ($value !== '') {
                    $value = $this->stringify($value);
                    $valueBytes = strlen($value);
                    if ($this->output_bytes + $valueBytes > self::XT_SYNTAX_MAX_OUTPUT_BYTES) {
                        return 'XtScript Error: Output size limit exceeded.';
                    }
                    $this->output_bytes += $valueBytes;
                    $result[] = $value;
                }
            }

            return implode('', $result);
        } finally {
            if ($this->runtime_variable_registered) {
                $ctx->active_variable_bytes -= $this->variable_bytes;
                if ($ctx->active_variable_bytes < 0) {
                    $ctx->active_variable_bytes = 0;
                }
                $this->runtime_variable_registered = false;
            }

            --$ctx->execution_depth;

            if ($isRootExecution) {
                $ctx->started = null;
                $ctx->function_depth = 0;
            }
        }
    }

    private function parse_command($line)
    {
        $split = preg_split('#\\s+#', $line, 2);
        $cmd = strtolower(isset($split[0]) ? $split[0] : '');
        $rest = isset($split[1]) ? $split[1] : '';
        $args = array();

        if ($cmd === 'assign' || $cmd === 'var') {
            $args = explode('=', $rest, 2);
        } elseif ($cmd === 'include') {
            $args = array_map('trim', explode(',', $rest));
        } elseif ($cmd === 'call' || $cmd === 'function') {
            $parts = preg_split('#\\s+#', trim($rest), 2);
            $function = isset($parts[0]) ? $parts[0] : '';
            $args = array($function);

            if (isset($parts[1]) && trim($parts[1]) !== '') {
                $argumentCount = 0;
                foreach (explode(';', $parts[1]) as $argument) {
                    if (++$argumentCount > self::XT_SYNTAX_MAX_FUNCTION_ARGS) {
                        break;
                    }
                    $argument = trim($argument);
                    if ($argument === '') {
                        continue;
                    }

                    $pair = explode('=', $argument, 2);
                    $name = trim($pair[0]);
                    if ($name === '') {
                        continue;
                    }

                    $args[$name] = isset($pair[1]) ? $pair[1] : '';
                }
            }
        } elseif ($rest !== '') {
            $args = $rest;
        }

        return array($cmd, $args);
    }

    private function build_indexes()
    {
        $this->xt_syntax_indexes = array();

        foreach ($this->cmd_list as $key => $line) {
            $line = trim(trim($line), ';');
            if ($line !== '' && $line[0] === '@') {
                $this->xt_syntax_indexes[$line] = $key;
            }
        }
    }

    private function get_index($mark)
    {
        return isset($this->xt_syntax_indexes[$mark]) ? $this->xt_syntax_indexes[$mark] : false;
    }

    private function eval_cmd($cmd, $args, $rawLine = '')
    {
        if (!is_array($args)) {
            $args = array($args);
        }

        $result = '';
        $state = $this->syntax_get_state();

        // Function capture mode. Only the matching endfunction terminates capture.
        if ($state === self::XT_SYNTAX_FUNCTION) {
            if ($cmd === 'endfunction') {
                $this->syntax_pop_state();
                $this->active_function = null;
                return '';
            }

            $function = $this->active_function;
            if ($function !== null && isset($this->xt_syntax_functions[$function]['code'])) {
                $this->xt_syntax_functions[$function]['code'] .= trim($rawLine) . "\n";
            }

            return '';
        }

        // FUNCTION_IGNORE is used both after return and while discarding an invalid function body.
        if ($state === self::XT_SYNTAX_FUNCTION_IGNORE) {
            if ($cmd === 'endfunction') {
                $this->syntax_pop_state();
                $this->active_function = null;
            }
            return '';
        }

        // Properly account for nested IF blocks while an outer branch is skipped.
        if ($state === self::XT_SYNTAX_IF_SKIP) {
            if ($cmd === 'if') {
                $this->syntax_push_state(self::XT_SYNTAX_IF_SKIP);
            } elseif ($cmd === 'endif') {
                $this->syntax_pop_state();
            }
            return '';
        }

        if ($state === self::XT_SYNTAX_IF_FALSE) {
            if ($cmd === 'if') {
                $this->syntax_push_state(self::XT_SYNTAX_IF_SKIP);
                return '';
            }

            if ($cmd === 'endif') {
                $this->syntax_pop_state();
                return '';
            }

            if ($cmd !== 'else' && $cmd !== 'elseif') {
                return '';
            }
        }

        if ($state === self::XT_SYNTAX_IF_TRUE) {
            if ($cmd === 'endif') {
                $this->syntax_pop_state();
                return '';
            }

            if ($cmd === 'else' || $cmd === 'elseif') {
                $this->syntax_set_state(self::XT_SYNTAX_IF_SKIP);
                return '';
            }
        }

        if ($state === self::XT_SYNTAX_IF_FALSE_ELSE) {
            if ($cmd === 'if') {
                // A true nested IF should be evaluated normally, so do not intercept it.
            } elseif ($cmd === 'endif') {
                $this->syntax_pop_state();
                return '';
            } elseif ($cmd === 'else' || $cmd === 'elseif') {
                $this->syntax_set_state(self::XT_SYNTAX_IF_SKIP);
                return '';
            }
        }

        $args = array_map(static function ($value) {
            return is_string($value) ? trim($value) : $value;
        }, $args);

        if ($cmd === 'assign' || $cmd === 'var') {
            if (count($args) === 2 && $args[0] !== '') {
                $name = $args[0];
                $value = $args[1];

                if (substr($value, 0, 4) === '<xt:') {
                    $value = $this->eval_vars($value);
                    if (class_exists('content_model')) {
                        $value = content_model::parse_xt($value, $this->url, $this->info);
                    }
                    $this->set_var($name, $this->eval_vars($value));
                } elseif (strpos($value, 'call ') === 0) {
                    list($function, $callArgs) = $this->parse_inline_call(substr($value, 5));
                    $this->set_var($name, $this->eval_function($function, $callArgs));
                } else {
                    $this->set_var($name, $this->eval_vars($value));
                }
            }
        } elseif ($cmd === 'del' || $cmd === 'delete') {
            if (isset($args[0])) {
                $this->unset_var($args[0]);
            }
        } elseif ($cmd === 'get') {
            if (isset($args[0])) {
                $value = isset($this->vars[$args[0]]) ? $this->vars[$args[0]] : '';
                $this->set_var('$' . $args[0], $this->common_get_param($value, ''));
            }
        } elseif ($cmd === 'get_or_default') {
            if (isset($args[0])) {
                $parts = explode(';', $args[0], 2);
                $name = isset($parts[0]) ? trim($parts[0]) : '';
                $default = isset($parts[1]) ? $parts[1] : '';

                if ($name !== '' && isset($this->vars[$name]) && $this->vars[$name] !== '') {
                    $this->set_var('$' . $name, $this->vars[$name]);
                } elseif ($name !== '') {
                    $this->set_var('$' . $name, $this->common_get_param($default, ''));
                }
            }
        } elseif ($cmd === 'print' || $cmd === 'return') {
            if (isset($args[0]) && array_key_exists($args[0], $this->vars)) {
                $result = $this->vars[$args[0]];
            } elseif (isset($args[0]) && $args[0] !== '') {
                $result = $this->eval_vars($args[0]);
            }

            if ($cmd === 'return') {
                $this->syntax_set_state(self::XT_SYNTAX_FUNCTION_IGNORE);
            }
        } elseif ($cmd === 'print_raw') {
            $result = isset($args[0]) ? $args[0] : '';
        } elseif ($cmd === 'call') {
            $function = array_shift($args);
            $result = $this->eval_function((string) $function, $args);
        } elseif ($cmd === 'if' || ($cmd === 'elseif' && $state === self::XT_SYNTAX_IF_FALSE)) {
            $expression = isset($args[0]) ? $args[0] : '';
            $matched = $this->eval_boolean_expression($expression);

            $newState = $matched ? self::XT_SYNTAX_IF_TRUE : self::XT_SYNTAX_IF_FALSE;

            if ($cmd === 'elseif' && $matched) {
                $newState = self::XT_SYNTAX_IF_FALSE_ELSE;
            }

            if ($cmd === 'if') {
                $this->syntax_push_state($newState);
            } else {
                $this->syntax_set_state($newState);
            }
        } elseif ($cmd === 'else') {
            if ($state === self::XT_SYNTAX_IF_FALSE) {
                $this->syntax_set_state(self::XT_SYNTAX_IF_FALSE_ELSE);
            } elseif ($state === self::XT_SYNTAX_IF_FALSE_ELSE) {
                $this->syntax_set_state(self::XT_SYNTAX_IF_SKIP);
            }
        } elseif ($cmd === 'elseif') {
            $this->syntax_set_state(self::XT_SYNTAX_IF_SKIP);
        } elseif ($cmd === 'endif') {
            // Stray endif: ignore instead of corrupting the root state.
            if (count($this->xt_syntax_state) > 1) {
                $this->syntax_pop_state();
            }
        } elseif ($cmd === 'goto') {
            $mark = isset($args[0]) ? $args[0] : '';
            if ($mark !== '' && $mark[0] === '@') {
                $neededIndex = $this->get_index($mark);
                if ($neededIndex !== false) {
                    if (++$this->goto_count > self::XT_SYNTAX_MAX_GOTO) {
                        return 'XtScript Error: Maximum goto limit reached.';
                    }
                    $this->program_counter = $neededIndex;
                }
            }
        } elseif ($cmd === 'function') {
            $function = (string) array_shift($args);
            if ($function === '') {
                return 'XtScript Error: Invalid function name.';
            }

            if ($this->is_native_function($function)) {
                $result = 'XtScript Error: Trying to overload native `' . $this->error_token($function) . '` function.';
                $this->active_function = $function;
                $this->syntax_push_state(self::XT_SYNTAX_FUNCTION_IGNORE);
            } elseif (!$this->is_valid_function_name($function)) {
                $result = 'XtScript Error: Invalid function name `' . $this->error_token($function) . '`.';
                $this->active_function = $function;
                $this->syntax_push_state(self::XT_SYNTAX_FUNCTION_IGNORE);
            } else {
                if (!array_key_exists($function, $this->xt_syntax_functions)
                    && count($this->xt_syntax_functions) >= self::XT_SYNTAX_MAX_FUNCTIONS) {
                    return 'XtScript Error: Maximum function count reached.';
                }
                $this->active_function = $function;
                $this->syntax_push_state(self::XT_SYNTAX_FUNCTION);
                $this->xt_syntax_functions[$function] = array('args' => $args, 'code' => '');
            }
        } elseif ($cmd === 'endfunction') {
            // Stray endfunction outside function capture: ignore.
        } elseif ($cmd === 'include') {
            $result = $this->eval_include($args);
        }

        return $this->stringify($result);
    }

    private function parse_inline_call($code)
    {
        $parts = preg_split('#\\s+#', trim($code), 2);
        $function = isset($parts[0]) ? $parts[0] : '';
        $vars = array();

        if (isset($parts[1]) && trim($parts[1]) !== '') {
            $argumentCount = 0;
            foreach (explode(';', $parts[1]) as $argument) {
                if (++$argumentCount > self::XT_SYNTAX_MAX_FUNCTION_ARGS) {
                    break;
                }
                $argument = trim($argument);
                if ($argument === '') {
                    continue;
                }

                $pair = explode('=', $argument, 2);
                $name = trim($pair[0]);
                if ($name === '') {
                    continue;
                }
                $vars[$name] = isset($pair[1]) ? $pair[1] : '';
            }
        }

        return array($function, $vars);
    }

    private function eval_include($args)
    {
        if (!class_exists('X')) {
            return 'XtScript Error: Filesystem unavailable.';
        }

        if ($this->runtime_context->include_depth >= self::XT_SYNTAX_MAX_INCLUDE_DEPTH) {
            return 'XtScript Error: Maximum include depth reached.';
        }

        $fs = X::model('filesystem');
        if (!is_object($fs) || !method_exists($fs, 'path')) {
            return 'XtScript Error: Filesystem unavailable.';
        }

        $slash = strpos((string) $this->url, '/');
        $domain = $slash === false ? (string) $this->url : substr((string) $this->url, 0, $slash);
        $domainPath = $fs->path($domain);
        $path = $fs->path(dirname((string) $this->url));

        if (!is_array($domainPath) || !isset($domainPath['absolute']) || !is_array($path) || !isset($path['absolute'])) {
            return 'XtScript Error: Invalid filesystem path.';
        }

        $domainRoot = realpath($domainPath['absolute']);
        $currentRoot = realpath($path['absolute']);

        if ($domainRoot === false || $currentRoot === false
            || $this->is_filesystem_root($domainRoot)
            || !$this->path_is_within($currentRoot, $domainRoot)) {
            return 'XtScript Error: Invalid filesystem path.';
        }

        $result = '';
        ++$this->runtime_context->include_depth;

        try {
            foreach ($args as $arg) {
                if (++$this->runtime_context->include_files > self::XT_SYNTAX_MAX_INCLUDE_FILES) {
                    return 'XtScript Error: Maximum include file count reached.';
                }

                $arg = trim((string) $arg);
                if ($arg === '' || strpos($arg, "\0") !== false || preg_match('#[\x00-\x1F\x7F]#', $arg)) {
                    continue;
                }

                if (strtolower(substr($arg, -3)) !== '.xt') {
                    continue;
                }

                $p = $fs->path($arg);
                $functionsPrefix = '';
                $checkOwner = false;
                $file = false;
                $fileRoot = $domainRoot;

                if (!is_array($p) || !isset($p['absolute'])) {
                    if ($arg[0] === '/') {
                        $candidate = $domainRoot . DIRECTORY_SEPARATOR . ltrim($arg, '/\\');
                    } else {
                        $candidate = $currentRoot . DIRECTORY_SEPARATOR . $arg;
                    }

                    $file = realpath($candidate);
                    if ($file !== false && !$this->path_is_within($file, $domainRoot)) {
                        $file = false;
                    }
                } else {
                    $slashPos = strpos($arg, '/');
                    $functionsPrefix = $slashPos === false ? '' : substr($arg, 0, $slashPos);
                    if ($functionsPrefix === '' || !$this->is_valid_site_identifier($functionsPrefix)) {
                        continue;
                    }

                    $targetRootData = $fs->path($functionsPrefix);
                    if (!is_array($targetRootData) || !isset($targetRootData['absolute'])) {
                        continue;
                    }
                    $targetRoot = realpath($targetRootData['absolute']);
                    $file = realpath($p['absolute']);
                    if ($targetRoot === false || $this->is_filesystem_root($targetRoot)
                        || $file === false || !$this->path_is_within($file, $targetRoot)) {
                        $file = false;
                    } else {
                        $checkOwner = true;
                        $fileRoot = $targetRoot;
                    }
                }

                if ($file === false || !is_file($file) || !is_readable($file)
                    || strtolower(pathinfo($file, PATHINFO_EXTENSION)) !== 'xt'
                    || $this->is_sensitive_file_path($file, $fileRoot)) {
                    continue;
                }

                $contents = $this->read_file_limited($file, self::XT_SYNTAX_MAX_INCLUDE_FILE_BYTES);
                if ($contents === false) {
                    continue;
                }

                $this->runtime_context->include_bytes += strlen($contents);
                if ($this->runtime_context->include_bytes > self::XT_SYNTAX_MAX_INCLUDE_TOTAL_BYTES) {
                    return 'XtScript Error: Total include size limit exceeded.';
                }

                $cfg = preg_split('#\r?\n#', $contents, 2);
                $firstLine = isset($cfg[0]) ? $cfg[0] : '';

                if ($checkOwner && !$this->is_exportable_header($firstLine)) {
                    continue;
                }

                $version = 1;
                if (preg_match('#\bversion\s*(\d+)\b#i', $firstLine, $match)) {
                    $version = (int) $match[1];
                }

                $functions = array();
                $vars = ($checkOwner || !$this->request_vars_allowed) ? array() : $this->build_request_vars();
                $originVars = $vars;
                $executionUrl = $checkOwner
                    ? ltrim(str_replace('\\', '/', $arg), '/')
                    : $this->url;
                $executionInfo = $checkOwner ? array() : $this->info;

                $obj = new script($executionUrl, $executionInfo, $vars, $functions);
                $obj->runtime_context = $this->runtime_context;
                $obj->allowed_plugins_override = $this->allowed_plugins_override;
                $obj->debug_functions_enabled_override = $this->debug_functions_enabled_override;
                $obj->request_vars_allowed = $checkOwner ? false : $this->request_vars_allowed;
                $obj->isolated_execution = $checkOwner ? true : $this->isolated_execution;
                $piece = $obj->eval_syntax($contents, $version);
                if (strlen($result) + strlen($piece) > self::XT_SYNTAX_MAX_OUTPUT_BYTES) {
                    return 'XtScript Error: Output size limit exceeded.';
                }
                $result .= $piece;

                $dependencyOrigins = array();
                if ($checkOwner) {
                    $dependencyOrigins[$this->normalize_execution_origin($executionUrl)] = true;
                    foreach ($functions as $dependencyCode) {
                        if (is_array($dependencyCode) && !empty($dependencyCode['isolated']) && isset($dependencyCode['origin_url'])) {
                            $dependencyOrigin = $this->normalize_execution_origin((string) $dependencyCode['origin_url']);
                            if ($dependencyOrigin !== '') {
                                $dependencyOrigins[$dependencyOrigin] = true;
                            }
                        }
                    }
                }

                foreach ($functions as $function => $code) {
                    if (count($this->xt_syntax_functions) >= self::XT_SYNTAX_MAX_FUNCTIONS
                        && !array_key_exists($functionsPrefix . '@' . $function, $this->xt_syntax_functions)) {
                        return 'XtScript Error: Maximum function count reached.';
                    }
                    if (!$checkOwner && $this->isolated_execution && is_array($code)) {
                        $code['internal_only'] = true;
                    }
                    if ($checkOwner && is_array($code)) {
                        if (empty($code['isolated'])) {
                            $code['origin_url'] = $executionUrl;
                            $code['origin_info'] = array();
                            $code['isolated'] = true;
                            $code['environment'] = $vars;
                            $code['origin_name'] = (string) $function;
                            $code['allowed_origin_urls'] = array_keys($dependencyOrigins);
                        } else {
                            $ownOrigin = isset($code['origin_url'])
                                ? $this->normalize_execution_origin((string) $code['origin_url'])
                                : '';
                            if (!isset($code['allowed_origin_urls']) || !is_array($code['allowed_origin_urls'])) {
                                $code['allowed_origin_urls'] = $ownOrigin === '' ? array() : array($ownOrigin);
                            } elseif ($ownOrigin !== '' && !in_array($ownOrigin, $code['allowed_origin_urls'], true)) {
                                $code['allowed_origin_urls'][] = $ownOrigin;
                            }
                        }
                        if (!isset($code['import_aliases']) || !is_array($code['import_aliases'])) {
                            $code['import_aliases'] = array();
                        }
                        $alias = (string) $function;
                        if ($this->is_valid_registry_function_name($alias) && !in_array($alias, $code['import_aliases'], true)) {
                            $code['import_aliases'][] = $alias;
                        }
                    }
                    $this->xt_syntax_functions[$functionsPrefix . '@' . $function] = $code;
                }

                foreach ($vars as $key => $var) {
                    if (!array_key_exists($key, $originVars) || $originVars[$key] != $var) {
                        $name = $functionsPrefix . '@' . $key;
                        $this->set_var($name, $var);
                    }
                }
            }
        } finally {
            --$this->runtime_context->include_depth;
        }

        return $result;
    }

    private function path_is_within($path, $root)
    {
        $path = str_replace('\\', '/', (string) $path);
        $root = str_replace('\\', '/', (string) $root);
        $path = $path === '/' ? '/' : rtrim($path, '/');
        $root = $root === '/' ? '/' : rtrim($root, '/');

        if ($path === '' || $root === '') {
            return false;
        }
        if ($root === '/') {
            return $path[0] === '/';
        }
        return $path === $root || strpos($path . '/', $root . '/') === 0;
    }


    private function is_valid_site_identifier($value)
    {
        return preg_match('#^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$#', (string) $value) === 1
            && strpos((string) $value, '..') === false;
    }

    private function is_exportable_header($firstLine)
    {
        $line = trim((string) $firstLine);
        if ($line === '') {
            return false;
        }

        // Strip UTF-8 BOM and the optional comment marker used by legacy headers.
        if (substr($line, 0, 3) === "\xEF\xBB\xBF") {
            $line = substr($line, 3);
        }
        $line = ltrim($line);
        if (isset($line[0]) && $line[0] === '#') {
            $line = ltrim(substr($line, 1));
        }

        // Normalize common directive separators, then accept only a small explicit grammar.
        $line = strtolower(trim(str_replace(array(',', ';', ':'), ' ', $line)));
        $line = preg_replace('#\s+#', ' ', $line);
        if (!is_string($line) || $line === '') {
            return false;
        }

        $patterns = array(
            '#^exportable$#',
            '#^exportable\s+(?:true|1|on)$#',
            '#^exportable\s*=\s*(?:true|1|on)$#',
            '#^version\s*\d+\s+exportable$#',
            '#^version\s*\d+\s+exportable\s+(?:true|1|on)$#',
            '#^exportable\s+version\s*\d+$#',
            '#^exportable\s+(?:true|1|on)\s+version\s*\d+$#'
        );

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $line) === 1) {
                return true;
            }
        }

        return false;
    }

    private function read_file_limited($file, $maxBytes)
    {
        $expectedCanonical = realpath((string) $file);
        if ($expectedCanonical === false) {
            return false;
        }

        $handle = @fopen($expectedCanonical, 'rb');
        if ($handle === false) {
            return false;
        }

        $data = '';
        try {
            // Revalidate after opening to narrow the realpath()/open TOCTOU
            // window. If a file or parent path was swapped, either the
            // canonical path or the opened inode will no longer match.
            clearstatcache(true, $expectedCanonical);
            $afterCanonical = realpath($expectedCanonical);
            $handleStat = @fstat($handle);
            $pathStat = @stat($expectedCanonical);
            if ($afterCanonical === false || $afterCanonical !== $expectedCanonical
                || !is_array($handleStat) || !is_array($pathStat)) {
                return false;
            }
            if (isset($handleStat['dev'], $handleStat['ino'], $pathStat['dev'], $pathStat['ino'])
                && ((string) $handleStat['dev'] !== (string) $pathStat['dev']
                    || (string) $handleStat['ino'] !== (string) $pathStat['ino'])) {
                return false;
            }

            while (!feof($handle)) {
                $remaining = $maxBytes + 1 - strlen($data);
                if ($remaining <= 0) {
                    return false;
                }
                $chunk = fread($handle, min(65536, $remaining));
                if ($chunk === false) {
                    return false;
                }
                $data .= $chunk;
                if (strlen($data) > $maxBytes) {
                    return false;
                }
            }
        } finally {
            fclose($handle);
        }

        return $data;
    }

    private function build_request_vars()
    {
        $vars = array();
        $count = 0;
        $totalBytes = 0;
        $sources = array();

        if (isset($_GET) && is_array($_GET)) {
            $sources[] = $_GET;
        }
        if (isset($_POST) && is_array($_POST) && $_POST !== array()) {
            $sources[] = $_POST;
        }

        // Iterate sources directly instead of array_merge() so an attacker
        // cannot force a second full in-memory copy before the request budgets
        // are applied. POST keeps the legacy behavior of overriding GET.
        foreach ($sources as $source) {
            foreach ($source as $key => $value) {
                if (!is_scalar($value) && $value !== null) {
                    continue;
                }

                $key = (string) $key;
                $value = $value === null ? '' : (string) $value;
                if (strlen($key) > self::XT_SYNTAX_MAX_VARIABLE_NAME_BYTES
                    || strlen($value) > self::XT_SYNTAX_MAX_REQUEST_VALUE_BYTES) {
                    continue;
                }

                $entryBytes = strlen($key) + strlen($value);
                if (array_key_exists($key, $vars)) {
                    $oldBytes = strlen($key) + strlen((string) $vars[$key]);
                    if ($totalBytes - $oldBytes + $entryBytes > self::XT_SYNTAX_MAX_REQUEST_TOTAL_BYTES) {
                        continue;
                    }
                    $totalBytes = $totalBytes - $oldBytes + $entryBytes;
                    $vars[$key] = $value;
                    continue;
                }

                if ($count >= self::XT_SYNTAX_MAX_REQUEST_VARS
                    || $totalBytes + $entryBytes > self::XT_SYNTAX_MAX_REQUEST_TOTAL_BYTES) {
                    continue;
                }

                ++$count;
                $totalBytes += $entryBytes;
                $vars[$key] = $value;
            }
        }

        return $vars;
    }

    private function refresh_variable_budget()
    {
        $count = 0;
        $bytes = 0;

        foreach ($this->vars as $name => $value) {
            ++$count;
            if ($count > self::XT_SYNTAX_MAX_VARIABLES) {
                $this->setup_error = 'XtScript Error: Maximum variable count reached.';
                return false;
            }

            $name = (string) $name;
            if (strlen($name) > self::XT_SYNTAX_MAX_VARIABLE_NAME_BYTES) {
                $this->setup_error = 'XtScript Error: Variable name too long.';
                return false;
            }

            $bytes += strlen($name) + $this->value_storage_bytes($value);
            if ($bytes > self::XT_SYNTAX_MAX_VARIABLE_BYTES) {
                $this->setup_error = 'XtScript Error: Variable storage limit exceeded.';
                return false;
            }
        }

        $this->variable_bytes = $bytes;
        $this->setup_error = null;
        return true;
    }

    private function value_storage_bytes($value)
    {
        if ($value === null || is_bool($value)) {
            return 1;
        }
        if (is_int($value) || is_float($value)) {
            return strlen((string) $value);
        }
        if (is_string($value)) {
            return strlen($value);
        }
        if (is_array($value)) {
            return min(self::XT_SYNTAX_MAX_VARIABLE_BYTES + 1, count($value) * 64);
        }
        return 64;
    }

    private function set_var($name, $value)
    {
        $name = (string) $name;
        if ($name === '' || strlen($name) > self::XT_SYNTAX_MAX_VARIABLE_NAME_BYTES) {
            throw new RuntimeException('XtScript variable name limit exceeded.');
        }

        $value = $this->limit_value($value);
        $exists = array_key_exists($name, $this->vars);
        $oldBytes = $exists ? strlen($name) + $this->value_storage_bytes($this->vars[$name]) : 0;
        $newBytes = strlen($name) + $this->value_storage_bytes($value);
        $newCount = count($this->vars) + ($exists ? 0 : 1);

        if ($newCount > self::XT_SYNTAX_MAX_VARIABLES) {
            throw new RuntimeException('XtScript variable count limit exceeded.');
        }
        $delta = $newBytes - $oldBytes;
        if ($this->variable_bytes + $delta > self::XT_SYNTAX_MAX_VARIABLE_BYTES) {
            throw new RuntimeException('XtScript variable storage limit exceeded.');
        }
        if ($this->runtime_variable_registered
            && $this->runtime_context->active_variable_bytes + $delta > self::XT_SYNTAX_MAX_ACTIVE_VARIABLE_BYTES) {
            throw new RuntimeException('XtScript active variable memory limit exceeded.');
        }

        $this->vars[$name] = $value;
        $this->variable_bytes += $delta;
        if ($this->runtime_variable_registered) {
            $this->runtime_context->active_variable_bytes += $delta;
        }
        return $value;
    }

    private function unset_var($name)
    {
        $name = (string) $name;
        if (!array_key_exists($name, $this->vars)) {
            return;
        }
        $removedBytes = strlen($name) + $this->value_storage_bytes($this->vars[$name]);
        $this->variable_bytes -= $removedBytes;
        if ($this->variable_bytes < 0) {
            $this->variable_bytes = 0;
        }
        if ($this->runtime_variable_registered) {
            $this->runtime_context->active_variable_bytes -= $removedBytes;
            if ($this->runtime_context->active_variable_bytes < 0) {
                $this->runtime_context->active_variable_bytes = 0;
            }
        }
        unset($this->vars[$name]);
    }

    private function limit_value($value)
    {
        $value = $this->stringify($value);
        if (strlen($value) > self::XT_SYNTAX_MAX_VALUE_BYTES) {
            throw new RuntimeException('XtScript value size limit exceeded.');
        }
        return $value;
    }

    private function replace_pattern_bounded($pattern, $input, $callback)
    {
        $output = '';
        $offset = 0;
        $length = strlen($input);

        while ($offset < $length && preg_match($pattern, $input, $match, PREG_OFFSET_CAPTURE, $offset)) {
            $matched = $match[0][0];
            $position = $match[0][1];
            $prefix = substr($input, $offset, $position - $offset);
            $replacement = (string) $callback($matched);

            if (strlen($output) + strlen($prefix) + strlen($replacement) > self::XT_SYNTAX_MAX_VALUE_BYTES) {
                throw new RuntimeException('XtScript value size limit exceeded.');
            }

            $output .= $prefix . $replacement;
            $offset = $position + strlen($matched);
        }

        $tail = substr($input, $offset);
        if (strlen($output) + strlen($tail) > self::XT_SYNTAX_MAX_VALUE_BYTES) {
            throw new RuntimeException('XtScript value size limit exceeded.');
        }
        return $output . $tail;
    }

    private function eval_boolean_expression($expression)
    {
        $orGroups = preg_split('#\\s+or\\s+#i', trim((string) $expression));

        foreach ($orGroups as $orGroup) {
            $andConditions = preg_split('#\\s+and\\s+#i', trim($orGroup));
            $andResult = true;

            foreach ($andConditions as $condition) {
                if (!$this->eval_single_condition($condition)) {
                    $andResult = false;
                    break;
                }
            }

            if ($andResult) {
                return true;
            }
        }

        return false;
    }

    private function eval_single_condition($expression)
    {
        $expression = trim((string) $expression);
        $inverse = false;

        if (preg_match('#^not\\s+#i', $expression)) {
            $expression = preg_replace('#^not\\s+#i', '', $expression, 1);
            $inverse = true;
        }

        $operators = array('===', '!==', '>=', '<=', '==', '!=', '>', '<');
        $operator = 'bool';
        $condition = array($expression);

        foreach ($operators as $candidate) {
            $position = strpos($expression, $candidate);
            if ($position !== false) {
                $operator = $candidate;
                $condition = array(
                    trim(substr($expression, 0, $position)),
                    trim(substr($expression, $position + strlen($candidate)))
                );
                break;
            }
        }

        $result = $this->eval_condition($operator, $condition);
        return $inverse ? !$result : $result;
    }

    private function eval_condition($operator, $args)
    {
        if (!isset($args[0])) {
            return false;
        }

        $arg1 = $this->eval_vars($args[0]);

        if ($operator === 'bool') {
            return $this->to_bool($arg1);
        }

        if (!isset($args[1])) {
            return false;
        }

        $arg2 = $this->eval_vars($args[1]);

        switch ($operator) {
            case '>':
                return $arg1 > $arg2;
            case '<':
                return $arg1 < $arg2;
            case '==':
                return $arg1 == $arg2;
            case '===':
                return $arg1 === $arg2;
            case '!=':
                return $arg1 != $arg2;
            case '!==':
                return $arg1 !== $arg2;
            case '>=':
                return $arg1 >= $arg2;
            case '<=':
                return $arg1 <= $arg2;
        }

        return false;
    }

    private function to_bool($value)
    {
        if ($value === '' || $value === '0' || $value === 0 || $value === 0.0 || $value === null || $value === false) {
            return false;
        }
        return true;
    }

    private function eval_vars($result)
    {
        $result = $this->limit_value($result);
        $result = str_replace(array('\$', '\(', '\)'), array('&#36;', '&#40;', '&#41;'), $result);

        if (strpos($result, '$') !== false) {
            $result = $this->replace_pattern_bounded(
                '#[\w.]*@\$\w+#',
                $result,
                function ($name) {
                    return array_key_exists($name, $this->vars)
                        ? $this->limit_value($this->vars[$name])
                        : $name;
                }
            );

            $result = $this->replace_pattern_bounded(
                '#\$\w+#',
                $result,
                function ($name) {
                    return array_key_exists($name, $this->vars)
                        ? $this->limit_value($this->vars[$name])
                        : '';
                }
            );
        }

        if (strpos($result, '(') !== false && strpos($result, ')') !== false) {
            for ($i = 0; $i < 64; ++$i) {
                $changed = false;
                $result = preg_replace_callback(
                    '#\(([^()]*)\)#',
                    function ($matches) use (&$changed) {
                        $value = $this->eval_math($matches[1]);
                        if ($value === false) {
                            return $matches[0];
                        }
                        $changed = true;
                        return $this->stringify($value);
                    },
                    $result
                );

                if ($result === null) {
                    throw new RuntimeException('XtScript expression parsing failed.');
                }
                if (strlen($result) > self::XT_SYNTAX_MAX_VALUE_BYTES) {
                    throw new RuntimeException('XtScript value size limit exceeded.');
                }
                if (!$changed) {
                    break;
                }
            }
        }

        return $result;
    }

    private function eval_math($code)
    {
        $code = preg_replace('#\\s+#', '', (string) $code);
        if ($code === '' || preg_match('#^[0-9eE.+\\-*/%]+$#', $code) !== 1) {
            return false;
        }

        $position = 0;
        $value = $this->parse_math_expression($code, $position);

        if ($value === false || $position !== strlen($code)) {
            return false;
        }

        return $value;
    }

    private function parse_math_expression($code, &$position)
    {
        $left = $this->parse_math_term($code, $position);
        if ($left === false) {
            return false;
        }

        $length = strlen($code);
        while ($position < $length) {
            $operator = $code[$position];
            if ($operator !== '+' && $operator !== '-') {
                break;
            }

            ++$position;
            $right = $this->parse_math_term($code, $position);
            if ($right === false) {
                return false;
            }

            $left = $operator === '+' ? $left + $right : $left - $right;
        }

        return $left;
    }

    private function parse_math_term($code, &$position)
    {
        $left = $this->parse_math_number($code, $position);
        if ($left === false) {
            return false;
        }

        $length = strlen($code);
        while ($position < $length) {
            $operator = $code[$position];
            if ($operator !== '*' && $operator !== '/' && $operator !== '%') {
                break;
            }

            ++$position;
            $right = $this->parse_math_number($code, $position);
            if ($right === false) {
                return false;
            }

            if (($operator === '/' || $operator === '%') && (float) $right == 0.0) {
                return false;
            }

            if ($operator === '*') {
                $left *= $right;
            } elseif ($operator === '/') {
                $left /= $right;
            } else {
                $left = (int) $left % (int) $right;
            }
        }

        return $left;
    }

    private function parse_math_number($code, &$position)
    {
        $length = strlen($code);
        if ($position >= $length) {
            return false;
        }

        $start = $position;
        if ($code[$position] === '+' || $code[$position] === '-') {
            ++$position;
        }

        $hasDigits = false;
        while ($position < $length && ($code[$position] >= '0' && $code[$position] <= '9')) {
            $hasDigits = true;
            ++$position;
        }

        if ($position < $length && $code[$position] === '.') {
            ++$position;
            while ($position < $length && ($code[$position] >= '0' && $code[$position] <= '9')) {
                $hasDigits = true;
                ++$position;
            }
        }

        if (!$hasDigits) {
            return false;
        }

        if ($position < $length && ($code[$position] === 'e' || $code[$position] === 'E')) {
            $exponentStart = $position;
            ++$position;
            if ($position < $length && ($code[$position] === '+' || $code[$position] === '-')) {
                ++$position;
            }

            $hasExponentDigits = false;
            while ($position < $length && ($code[$position] >= '0' && $code[$position] <= '9')) {
                $hasExponentDigits = true;
                ++$position;
            }

            if (!$hasExponentDigits) {
                $position = $exponentStart;
            }
        }

        $token = substr($code, $start, $position - $start);
        return strpbrk($token, '.eE') !== false ? (float) $token : (int) $token;
    }

    public function eval_function($function, $args)
    {
        $function = (string) $function;
        $args = is_array($args) ? $args : array();
        $method = '__' . $function;

        if (strpos($function, '::') !== false) {
            return $this->eval_plugin_function($function, $args);
        }

        if ($this->is_native_function($function) && method_exists($this, $method)) {
            foreach ($args as $key => $value) {
                $args[$key] = $this->eval_vars($value);
            }

            try {
                return $this->limit_value(call_user_func(array($this, $method), $args));
            } catch (Throwable $e) {
                return 'XtScript Error: Native function `' . $this->error_token($function) . '` failed.';
            }
        }

        if (!isset($this->xt_syntax_functions[$function]['code'])) {
            return 'XtScript Error: Undefined function `' . $this->error_token($function) . '`';
        }

        $definition = $this->xt_syntax_functions[$function];

        // Internal helpers imported while evaluating an isolated/exportable site
        // are capabilities of that origin only. Merely being in *some* isolated
        // execution is not enough, otherwise site B could call a private helper
        // belonging to site C when the caller happened to import both sites.
        if (!empty($definition['internal_only'])) {
            $originUrl = isset($definition['origin_url']) ? (string) $definition['origin_url'] : '';
            if (!$this->isolated_execution || $originUrl === '' || !$this->same_execution_origin($originUrl, (string) $this->url)) {
                return 'XtScript Error: Undefined function `' . $this->error_token($function) . '`';
            }
        }

        if ($this->runtime_context->function_depth >= self::XT_SYNTAX_MAX_FUNCTION_DEPTH) {
            return 'XtScript Error: Maximum function nesting level reached.';
        }

        ++$this->runtime_context->function_depth;

        try {
            $arguments = isset($definition['args']) ? $definition['args'] : array();

            foreach ($arguments as $key => $defaultValue) {
                if (array_key_exists($key, $args)) {
                    $arguments[$key] = $this->eval_vars($args[$key]);
                }
            }

            $isolated = !empty($definition['isolated']);
            $baseVars = $isolated && isset($definition['environment']) && is_array($definition['environment'])
                ? $definition['environment']
                : $this->vars;
            $executionUrl = $isolated && isset($definition['origin_url'])
                ? $definition['origin_url']
                : $this->url;
            $executionInfo = $isolated && array_key_exists('origin_info', $definition)
                ? $definition['origin_info']
                : $this->info;

            $vars = array_merge($baseVars, $arguments);

            if ($isolated) {
                $visibleFunctions = array();
                $allowedOrigins = array();
                if (isset($definition['allowed_origin_urls']) && is_array($definition['allowed_origin_urls'])) {
                    foreach ($definition['allowed_origin_urls'] as $allowedOrigin) {
                        $allowedOrigin = $this->normalize_execution_origin((string) $allowedOrigin);
                        if ($allowedOrigin !== '') {
                            $allowedOrigins[$allowedOrigin] = true;
                        }
                    }
                }
                $definitionOrigin = isset($definition['origin_url'])
                    ? $this->normalize_execution_origin((string) $definition['origin_url'])
                    : '';
                if ($definitionOrigin !== '') {
                    $allowedOrigins[$definitionOrigin] = true;
                }

                foreach ($this->xt_syntax_functions as $registeredName => $candidate) {
                    if (!is_array($candidate) || empty($candidate['isolated']) || !isset($candidate['origin_url'])) {
                        continue;
                    }
                    $candidateOrigin = $this->normalize_execution_origin((string) $candidate['origin_url']);
                    if ($candidateOrigin === '' || !isset($allowedOrigins[$candidateOrigin])) {
                        continue;
                    }

                    $visibleFunctions[$registeredName] = $candidate;

                    if (isset($candidate['origin_name'])
                        && isset($candidate['origin_url'])
                        && isset($definition['origin_url'])
                        && $candidate['origin_url'] === $definition['origin_url']
                        && $this->is_valid_registry_function_name($candidate['origin_name'])
                        && !isset($visibleFunctions[$candidate['origin_name']])) {
                        $visibleFunctions[$candidate['origin_name']] = $candidate;
                    }

                    if (isset($candidate['import_aliases']) && is_array($candidate['import_aliases'])) {
                        foreach ($candidate['import_aliases'] as $alias) {
                            $alias = (string) $alias;
                            if ($this->is_valid_registry_function_name($alias) && !isset($visibleFunctions[$alias])) {
                                $visibleFunctions[$alias] = $candidate;
                            }
                        }
                    }
                }

                $obj = new script($executionUrl, $executionInfo, $vars, $visibleFunctions);
                $obj->runtime_context = $this->runtime_context;
                $obj->allowed_plugins_override = $this->allowed_plugins_override;
                $obj->debug_functions_enabled_override = $this->debug_functions_enabled_override;
                $obj->request_vars_allowed = false;
                $obj->isolated_execution = true;
            } else {
                $obj = new script($executionUrl, $executionInfo, $vars, $this->xt_syntax_functions);
                $obj->runtime_context = $this->runtime_context;
                $obj->allowed_plugins_override = $this->allowed_plugins_override;
                $obj->debug_functions_enabled_override = $this->debug_functions_enabled_override;
                $obj->request_vars_allowed = $this->request_vars_allowed;
                $obj->isolated_execution = $this->isolated_execution;
            }

            return $obj->eval_syntax(
                $definition['code'],
                $this->version
            );
        } finally {
            --$this->runtime_context->function_depth;
        }
    }

    private function eval_plugin_function($function, $args)
    {
        list($class, $classMethod) = explode('::', $function, 2);

        if (!$this->is_valid_identifier($class) || !$this->is_valid_identifier($classMethod)) {
            return 'XtScript Error: Invalid plugin function.';
        }

        if (!$this->plugin_is_allowed($class)) {
            return 'XtScript Error: Plugin `' . $this->error_token($class) . '` is not enabled.';
        }

        if (++$this->runtime_context->plugin_calls > self::XT_SYNTAX_MAX_PLUGIN_CALLS) {
            return 'XtScript Error: Maximum plugin call count reached.';
        }

        $phpClass = 'xt_' . $class;

        if (!array_key_exists($class, $this->xt_syntax_plugins)) {
            $pluginFile = $this->xt_syntax_plugins_directory . 'xt_' . $class . '.php';
            $pluginRoot = realpath($this->xt_syntax_plugins_directory);
            $resolvedPlugin = realpath($pluginFile);
            $loaded = false;

            if ($pluginRoot !== false && $resolvedPlugin !== false
                && $this->path_is_within($resolvedPlugin, $pluginRoot)
                && is_file($resolvedPlugin) && is_readable($resolvedPlugin)
                && strtolower(pathinfo($resolvedPlugin, PATHINFO_EXTENSION)) === 'php') {
                try {
                    if (class_exists($phpClass, false)) {
                        // Refuse class-name hijacking by code loaded from some
                        // other file before this plugin is requested.
                        $reflection = new ReflectionClass($phpClass);
                        $classFile = $reflection->getFileName();
                        $loaded = is_string($classFile)
                            && realpath($classFile) === $resolvedPlugin;
                    } else {
                        require_once $resolvedPlugin;
                        if (class_exists($phpClass, false)) {
                            $reflection = new ReflectionClass($phpClass);
                            $classFile = $reflection->getFileName();
                            $loaded = is_string($classFile)
                                && realpath($classFile) === $resolvedPlugin;
                        }
                    }
                } catch (Throwable $e) {
                    $loaded = false;
                }
            }

            $this->xt_syntax_plugins[$class] = $loaded;
        }

        if (!$this->xt_syntax_plugins[$class]) {
            return 'XtScript Error: Undefined plugin `' . $this->error_token($class) . '`.';
        }

        // Cross-site/exportable code executes with a reduced capability set.
        // Plugins are arbitrary PHP and may touch request globals, databases,
        // networks or process state, so they are denied in isolated execution
        // unless that exact plugin explicitly opts in after its own audit.
        if ($this->isolated_execution && !$this->plugin_allows_isolated_execution($phpClass)) {
            return 'XtScript Error: Plugin `' . $this->error_token($class) . '` is not available in isolated execution.';
        }

        if (strpos($classMethod, '__') === 0 || $classMethod === '__setup') {
            return 'XtScript Error: Plugin function `' . $this->error_token($function) . '` is not exposed.';
        }

        $allowedMethods = $this->get_plugin_allowed_methods($phpClass);
        if (!isset($allowedMethods[$classMethod])) {
            return 'XtScript Error: Plugin function `' . $this->error_token($function) . '` is not exposed.';
        }

        try {
            $method = new ReflectionMethod($phpClass, $classMethod);
            if (!$method->isPublic() || !$method->isStatic() || $method->getDeclaringClass()->getName() !== $phpClass) {
                return 'XtScript Error: Plugin function `' . $this->error_token($function) . '` is not exposed.';
            }
        } catch (ReflectionException $e) {
            return 'XtScript Error: Undefined plugin function `' . $this->error_token($function) . '`.';
        }

        if (!$this->prepare_plugin_context($phpClass)) {
            return 'XtScript Error: Plugin context setup failed.';
        }

        foreach ($args as $key => $value) {
            $args[$key] = $this->eval_vars($value);
        }

        try {
            return $this->limit_value($method->invoke(null, $args));
        } catch (Throwable $e) {
            return 'XtScript Error: Plugin function `' . $this->error_token($function) . '` failed.';
        }
    }

    private function get_plugin_allowed_methods($phpClass)
    {
        $methods = array();
        try {
            if (defined($phpClass . '::XT_ALLOWED_METHODS')) {
                $declared = constant($phpClass . '::XT_ALLOWED_METHODS');
            } elseif (method_exists($phpClass, '__xt_allowed_methods')) {
                $reflection = new ReflectionMethod($phpClass, '__xt_allowed_methods');
                if (!$reflection->isPublic() || !$reflection->isStatic()) {
                    return $methods;
                }
                $declared = $reflection->invoke(null);
            } else {
                return $methods;
            }
        } catch (Throwable $e) {
            return $methods;
        }

        if (!is_array($declared)) {
            return $methods;
        }

        foreach ($declared as $name) {
            $name = (string) $name;
            if ($this->is_valid_identifier($name) && strpos($name, '__') !== 0 && $name !== '__setup') {
                $methods[$name] = true;
            }
        }
        return $methods;
    }

    private function plugin_is_allowed($class)
    {
        $allowed = $this->allowed_plugins_override !== null
            ? $this->allowed_plugins_override
            : self::$allowed_plugins;
        return isset($allowed[(string) $class]);
    }

    private function plugin_allows_isolated_execution($phpClass)
    {
        try {
            if (!defined($phpClass . '::XT_ALLOW_ISOLATED')) {
                return false;
            }
            return constant($phpClass . '::XT_ALLOW_ISOLATED') === true;
        } catch (Throwable $e) {
            return false;
        }
    }

    private function debug_functions_are_enabled()
    {
        return $this->debug_functions_enabled_override !== null
            ? (bool) $this->debug_functions_enabled_override
            : self::$debug_functions_enabled;
    }

    private function prepare_plugin_context($phpClass)
    {
        if (!method_exists($phpClass, '__setup')) {
            return true;
        }

        try {
            $setup = new ReflectionMethod($phpClass, '__setup');
            if (!$setup->isPublic() || !$setup->isStatic() || $setup->getDeclaringClass()->getName() !== $phpClass) {
                return false;
            }
            $setup->invoke(null, $this->url, $this->info);
            return true;
        } catch (Throwable $e) {
            return false;
        }
    }

    private function is_native_function($name)
    {
        static $allowed = null;
        if ($allowed === null) {
            $allowed = array_fill_keys(array(
                'dump_vars', 'dump_functions', 'args', 'execution_time', 'get_variable',
                'urlencode', 'urldecode', 'rawurlencode', 'rawurldecode', 'source', 'file_get_contents',
                'chr', 'ord', 'crc32', 'md5', 'sha1', 'base64_encode', 'base64_decode', 'bin2hex',
                'hex2bin', 'hexdec', 'dechex', 'htmlspecialchars', 'lcfirst', 'ucfirst', 'ucwords',
                'strtoupper', 'strtolower', 'trim', 'ltrim', 'rtrim', 'nl2br', 'br2nl', 'str_replace',
                'str_ireplace', 'str_pad', 'str_repeat', 'str_shuffle', 'strip_tags', 'addslashes',
                'stripslashes', 'strpos', 'strrpos', 'stripos', 'strripos', 'strstr', 'stristr',
                'strrchr', 'strrev', 'substr', 'strlen', 'abs', 'ceil', 'floor', 'round', 'mt_rand',
                'pi', 'pow', 'sqrt'
            ), true);
        }
        return isset($allowed[(string) $name]);
    }

    private function error_token($value)
    {
        $value = (string) $value;
        if (strlen($value) > 160) {
            $value = substr($value, 0, 160) . '...';
        }
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private function is_filesystem_root($path)
    {
        $real = realpath((string) $path);
        if ($real === false) {
            return false;
        }
        return dirname($real) === $real;
    }

    private function is_valid_registry_function_name($name)
    {
        return preg_match('#^@?[A-Za-z_][A-Za-z0-9_@.]*$#', (string) $name) === 1;
    }

    private function normalize_execution_origin($value)
    {
        $value = ltrim(str_replace('\\', '/', (string) $value), '/');
        if ($value === '') {
            return '';
        }
        $slash = strpos($value, '/');
        if ($slash === false) {
            return strtolower(rtrim($value, '.'));
        }
        $host = strtolower(rtrim(substr($value, 0, $slash), '.'));
        $path = substr($value, $slash);
        return $host . $path;
    }

    private function same_execution_origin($left, $right)
    {
        return $this->normalize_execution_origin($left) === $this->normalize_execution_origin($right);
    }

    private function is_valid_function_name($name)
    {
        return preg_match('#^[A-Za-z_][A-Za-z0-9_@.]*$#', (string) $name) === 1;
    }

    private function is_valid_identifier($name)
    {
        return preg_match('#^[A-Za-z_][A-Za-z0-9_]*$#', (string) $name) === 1;
    }

    private function has_timed_out()
    {
        return $this->runtime_context->started !== null
            && (microtime(true) - $this->runtime_context->started) > self::XT_SYNTAX_TIMEOUT;
    }

    private function syntax_push_state($state)
    {
        $this->xt_syntax_state[] = $state;
    }

    private function syntax_pop_state()
    {
        if (count($this->xt_syntax_state) <= 1) {
            return self::XT_SYNTAX_NONE;
        }
        return array_pop($this->xt_syntax_state);
    }

    private function syntax_set_state($state)
    {
        if (count($this->xt_syntax_state) <= 1) {
            $this->xt_syntax_state[0] = $state;
            return;
        }
        $this->xt_syntax_state[count($this->xt_syntax_state) - 1] = $state;
    }

    private function syntax_get_state()
    {
        return $this->xt_syntax_state[count($this->xt_syntax_state) - 1];
    }

    private function get_arg($args, $name, $default = '')
    {
        return array_key_exists($name, $args) ? $args[$name] : $default;
    }

    private function common_get_param($value, $default = '')
    {
        if (class_exists('common') && method_exists('common', 'get_param')) {
            return common::get_param($value, $default);
        }
        return ($value === null || $value === '') ? $default : $value;
    }

    private function stringify($value)
    {
        if ($value === null || $value === false) {
            return '';
        }
        if ($value === true) {
            return '1';
        }
        if (is_scalar($value)) {
            return (string) $value;
        }
        return '';
    }

    private function __dump_vars($args)
    {
        if (!$this->debug_functions_are_enabled()) {
            return 'XtScript Error: Debug functions are disabled.';
        }
        $tmp = $this->vars;
        unset($tmp['___p']);
        if (isset($tmp['code']) && empty($tmp['code'])) {
            unset($tmp['code']);
        }
        return '<pre>' . htmlspecialchars(print_r($tmp, true), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</pre>';
    }

    private function __dump_functions($args)
    {
        if (!$this->debug_functions_are_enabled()) {
            return 'XtScript Error: Debug functions are disabled.';
        }
        return '<pre>' . htmlspecialchars(print_r(array_keys($this->xt_syntax_functions), true), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</pre>';
    }

    private function __args($args)
    {
        if (!$this->debug_functions_are_enabled()) {
            return 'XtScript Error: Debug functions are disabled.';
        }
        return '<pre>' . htmlspecialchars(print_r($args, true), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</pre>';
    }

    private function __execution_time($args)
    {
        if ($this->runtime_context->started === null) {
            return '0.000000s.';
        }
        return number_format(microtime(true) - $this->runtime_context->started, 6, '.', '') . 's.';
    }

    private function __get_variable($args)
    {
        if (!isset($args['$name'])) {
            return '';
        }

        $name = str_replace('&#36;', '$', (string) $args['$name']);
        return array_key_exists($name, $this->vars) ? $this->vars[$name] : '';
    }

    private function __urlencode($args)
    {
        return isset($args['$val']) ? urlencode((string) $args['$val']) : '';
    }

    private function __urldecode($args)
    {
        return isset($args['$val']) ? urldecode((string) $args['$val']) : '';
    }

    private function __rawurlencode($args)
    {
        return isset($args['$val']) ? rawurlencode((string) $args['$val']) : '';
    }

    private function __rawurldecode($args)
    {
        return isset($args['$val']) ? rawurldecode((string) $args['$val']) : '';
    }

    private function __source($args)
    {
        return $this->__file_get_contents($args);
    }

    private function __file_get_contents($args)
    {
        if (!isset($args['$file']) || !class_exists('X')) {
            return '';
        }

        $requested = (string) $args['$file'];
        if ($requested === '' || strpos($requested, "\0") !== false || preg_match('#[\x00-\x1F\x7F]#', $requested)) {
            return '';
        }

        $fs = X::model('filesystem');
        if (!is_object($fs) || !method_exists($fs, 'path')) {
            return '';
        }

        $slash = strpos((string) $this->url, '/');
        $domain = $slash === false ? (string) $this->url : substr((string) $this->url, 0, $slash);
        $domainPath = $fs->path($domain);
        $path = $fs->path(dirname((string) $this->url));

        if (!is_array($domainPath) || !isset($domainPath['absolute']) || !is_array($path) || !isset($path['absolute'])) {
            return '';
        }

        $domainRoot = realpath($domainPath['absolute']);
        $currentRoot = realpath($path['absolute']);
        if ($domainRoot === false || $currentRoot === false
            || $this->is_filesystem_root($domainRoot)
            || !$this->path_is_within($currentRoot, $domainRoot)) {
            return '';
        }

        $baseRoot = ($requested[0] === '/' || $requested[0] === '\\') ? $domainRoot : $currentRoot;
        $file = realpath($baseRoot . DIRECTORY_SEPARATOR . ltrim($requested, '/\\'));
        if ($file === false || !$this->path_is_within($file, $domainRoot) || !is_file($file) || !is_readable($file)) {
            return '';
        }

        if ($this->is_sensitive_file_path($file, $domainRoot)) {
            return '';
        }

        $return = $this->read_file_limited($file, self::XT_SYNTAX_MAX_VALUE_BYTES);
        if ($return === false) {
            return '';
        }

        if ($this->to_bool($this->get_arg($args, '$html_safe', false))) {
            $return = htmlspecialchars($return, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }

        if ($this->to_bool($this->get_arg($args, '$nl2br', false))) {
            $return = nl2br($return);
        }

        if (array_key_exists('$space2nbsp', $args)) {
            $return = str_replace('  ', '&nbsp;&nbsp;', $return);
        }

        return $this->limit_value($return);
    }

    private function is_sensitive_file_path($file, $root)
    {
        $relative = ltrim(substr(str_replace('\\', '/', $file), strlen(rtrim(str_replace('\\', '/', $root), '/'))), '/');
        $segments = explode('/', $relative);
        foreach ($segments as $segment) {
            if ($segment !== '' && $segment[0] === '.') {
                return true;
            }
        }

        $basename = strtolower(basename($file));
        $blockedNames = array('.env', 'composer.json', 'composer.lock');
        if (in_array($basename, $blockedNames, true)) {
            return true;
        }

        $extension = strtolower(pathinfo($basename, PATHINFO_EXTENSION));
        return in_array($extension, array('php', 'phtml', 'phar', 'ini', 'env', 'key', 'pem', 'crt'), true);
    }

    // String / encoding functions.
    private function __chr($args)
    {
        return isset($args['$val']) ? chr((int) $args['$val']) : '';
    }

    private function __ord($args)
    {
        if (!isset($args['$val']) || (string) $args['$val'] === '') {
            return '';
        }
        return ord((string) $args['$val']);
    }

    private function __crc32($args)
    {
        return isset($args['$val']) ? crc32((string) $args['$val']) : '';
    }

    private function __md5($args)
    {
        return isset($args['$val']) ? md5((string) $args['$val']) : '';
    }

    private function __sha1($args)
    {
        return isset($args['$val']) ? sha1((string) $args['$val']) : '';
    }

    private function __base64_encode($args)
    {
        return isset($args['$val']) ? base64_encode((string) $args['$val']) : '';
    }

    private function __base64_decode($args)
    {
        if (!isset($args['$val'])) {
            return '';
        }
        $decoded = base64_decode((string) $args['$val'], false);
        return $decoded === false ? '' : $decoded;
    }

    private function __bin2hex($args)
    {
        return isset($args['$val']) ? bin2hex((string) $args['$val']) : '';
    }

    private function __hex2bin($args)
    {
        if (!isset($args['$val'])) {
            return '';
        }

        $value = (string) $args['$val'];
        if ($value === '' || (strlen($value) % 2) !== 0 || preg_match('/\A[0-9a-fA-F]+\z/D', $value) !== 1) {
            return '';
        }

        if (function_exists('hex2bin')) {
            $decoded = hex2bin($value);
            return $decoded === false ? '' : $decoded;
        }

        $bin = '';
        for ($i = 0, $len = strlen($value); $i < $len; $i += 2) {
            $bin .= chr(hexdec($value[$i] . $value[$i + 1]));
        }
        return $bin;
    }

    private function __hexdec($args)
    {
        return isset($args['$val']) ? hexdec((string) $args['$val']) : '';
    }

    private function __dechex($args)
    {
        return isset($args['$val']) ? dechex((int) $args['$val']) : '';
    }

    private function __htmlspecialchars($args)
    {
        if (!isset($args['$val'])) {
            return '';
        }

        $flags = defined('ENT_HTML401') ? ENT_COMPAT | ENT_HTML401 : ENT_COMPAT;
        $flagName = $this->get_arg($args, '$flags', null);
        if (is_string($flagName) && defined($flagName)) {
            $flags = constant($flagName);
        }

        $encoding = (string) $this->get_arg($args, '$encoding', 'UTF-8');
        $doubleEncode = $this->to_bool($this->get_arg($args, '$double_encode', true));

        // PHP emits a warning (not Throwable) for an unknown charset; contain it and keep legacy fallback behavior.
        return @htmlspecialchars((string) $args['$val'], $flags, $encoding, $doubleEncode);
    }

    private function __lcfirst($args)
    {
        return isset($args['$val']) ? lcfirst((string) $args['$val']) : '';
    }

    private function __ucfirst($args)
    {
        return isset($args['$val']) ? ucfirst((string) $args['$val']) : '';
    }

    private function __ucwords($args)
    {
        return isset($args['$val']) ? ucwords((string) $args['$val']) : '';
    }

    private function __strtoupper($args)
    {
        if (!isset($args['$val'])) {
            return '';
        }
        $value = (string) $args['$val'];
        return function_exists('mb_strtoupper') ? mb_strtoupper($value) : strtoupper($value);
    }

    private function __strtolower($args)
    {
        if (!isset($args['$val'])) {
            return '';
        }
        $value = (string) $args['$val'];
        return function_exists('mb_strtolower') ? mb_strtolower($value) : strtolower($value);
    }

    private function __trim($args)
    {
        return isset($args['$val'])
            ? trim((string) $args['$val'], (string) $this->get_arg($args, '$charlist', " \t\n\r\0\x0B"))
            : '';
    }

    private function __ltrim($args)
    {
        return isset($args['$val'])
            ? ltrim((string) $args['$val'], (string) $this->get_arg($args, '$charlist', " \t\n\r\0\x0B"))
            : '';
    }

    private function __rtrim($args)
    {
        return isset($args['$val'])
            ? rtrim((string) $args['$val'], (string) $this->get_arg($args, '$charlist', " \t\n\r\0\x0B"))
            : '';
    }

    private function __nl2br($args)
    {
        return isset($args['$val']) ? nl2br((string) $args['$val']) : '';
    }

    private function __br2nl($args)
    {
        if (!isset($args['$val'])) {
            return '';
        }
        return str_ireplace(array('<br>', '<br/>', '<br />'), "\n", (string) $args['$val']);
    }

    private function __str_replace($args)
    {
        return $this->safe_string_replace(false, $args);
    }

    private function __str_ireplace($args)
    {
        return $this->safe_string_replace(true, $args);
    }

    private function safe_string_replace($caseInsensitive, $args)
    {
        if (!isset($args['$subject'], $args['$replace'], $args['$search'])) {
            return '';
        }
        $subject = (string) $args['$subject'];
        $search = (string) $args['$search'];
        $replace = (string) $args['$replace'];
        if ($search !== '') {
            $count = $caseInsensitive
                ? substr_count(strtolower($subject), strtolower($search))
                : substr_count($subject, $search);
            $estimated = strlen($subject) + max(0, strlen($replace) - strlen($search)) * $count;
            if ($estimated > self::XT_SYNTAX_MAX_VALUE_BYTES) {
                return '';
            }
        }
        $value = $caseInsensitive
            ? str_ireplace($search, $replace, $subject)
            : str_replace($search, $replace, $subject);
        return $this->limit_value($value);
    }

    private function __str_pad($args)
    {
        if (!isset($args['$val'], $args['$pad_length'])) {
            return '';
        }

        $padType = STR_PAD_RIGHT;
        $padTypeName = $this->get_arg($args, '$pad_type', null);
        if (is_string($padTypeName) && defined($padTypeName)) {
            $candidatePadType = constant($padTypeName);
            if (in_array($candidatePadType, array(STR_PAD_LEFT, STR_PAD_RIGHT, STR_PAD_BOTH), true)) {
                $padType = $candidatePadType;
            }
        }

        $padString = (string) $this->get_arg($args, '$pad_string', ' ');
        if ($padString === '') {
            return '';
        }

        $padLength = max(0, (int) $args['$pad_length']);
        if ($padLength > self::XT_SYNTAX_MAX_VALUE_BYTES) {
            return '';
        }
        return $this->limit_value(str_pad(
            (string) $args['$val'],
            $padLength,
            $padString,
            $padType
        ));
    }

    private function __str_repeat($args)
    {
        if (!isset($args['$val'], $args['$multiplier'])) {
            return '';
        }
        $multiplier = (int) $args['$multiplier'];
        $value = (string) $args['$val'];
        if ($multiplier < 0 || ($value !== '' && strlen($value) > intdiv(self::XT_SYNTAX_MAX_VALUE_BYTES, max(1, $multiplier)))) {
            return '';
        }
        return $this->limit_value(str_repeat($value, $multiplier));
    }

    private function __str_shuffle($args)
    {
        return isset($args['$val']) ? str_shuffle((string) $args['$val']) : '';
    }

    private function __strip_tags($args)
    {
        return isset($args['$val'])
            ? strip_tags((string) $args['$val'], (string) $this->get_arg($args, '$allowable_tags', ''))
            : '';
    }

    private function __addslashes($args)
    {
        return isset($args['$val']) ? addslashes((string) $args['$val']) : '';
    }

    private function __stripslashes($args)
    {
        return isset($args['$val']) ? stripslashes((string) $args['$val']) : '';
    }

    private function __strpos($args)
    {
        return $this->string_position('strpos', $args);
    }

    private function __strrpos($args)
    {
        return $this->string_position('strrpos', $args);
    }

    private function __stripos($args)
    {
        return $this->string_position('stripos', $args);
    }

    private function __strripos($args)
    {
        return $this->string_position('strripos', $args);
    }

    private function string_position($function, $args)
    {
        if (!isset($args['$haystack'], $args['$needle'])) {
            return '';
        }

        $haystack = (string) $args['$haystack'];
        $needle = (string) $args['$needle'];
        $offset = (int) $this->get_arg($args, '$offset', 0);
        $length = strlen($haystack);

        if ($offset > $length) {
            $offset = 0;
        }
        if ($offset < -$length) {
            $offset = 0;
        }

        $result = $function($haystack, $needle, $offset);
        return $result === false ? '' : $result;
    }

    private function __strstr($args)
    {
        if (!isset($args['$haystack'], $args['$needle']) || (string) $args['$needle'] === '') {
            return '';
        }
        $result = strstr(
            (string) $args['$haystack'],
            (string) $args['$needle'],
            $this->to_bool($this->get_arg($args, '$before_needle', false))
        );
        return $result === false ? '' : $result;
    }

    private function __stristr($args)
    {
        if (!isset($args['$haystack'], $args['$needle']) || (string) $args['$needle'] === '') {
            return '';
        }
        $result = stristr(
            (string) $args['$haystack'],
            (string) $args['$needle'],
            $this->to_bool($this->get_arg($args, '$before_needle', false))
        );
        return $result === false ? '' : $result;
    }

    private function __strrchr($args)
    {
        if (!isset($args['$haystack'], $args['$needle']) || (string) $args['$needle'] === '') {
            return '';
        }
        $result = strrchr((string) $args['$haystack'], (string) $args['$needle']);
        return $result === false ? '' : $result;
    }

    private function __strrev($args)
    {
        return isset($args['$val']) ? strrev((string) $args['$val']) : '';
    }

    private function __substr($args)
    {
        if (!isset($args['$val'], $args['$start'])) {
            return '';
        }

        $value = (string) $args['$val'];
        $start = (int) $args['$start'];
        $result = array_key_exists('$length', $args)
            ? substr($value, $start, (int) $args['$length'])
            : substr($value, $start);

        return $result === false ? '' : $result;
    }

    private function __strlen($args)
    {
        if (!isset($args['$val'])) {
            return '';
        }
        $value = (string) $args['$val'];
        return function_exists('mb_strlen') ? mb_strlen($value) : strlen($value);
    }

    // Math functions.
    private function __abs($args)
    {
        return isset($args['$num']) ? abs((float) $args['$num']) : '';
    }

    private function __ceil($args)
    {
        return isset($args['$num']) ? ceil((float) $args['$num']) : '';
    }

    private function __floor($args)
    {
        return isset($args['$num']) ? floor((float) $args['$num']) : '';
    }

    private function __round($args)
    {
        if (!isset($args['$num'])) {
            return '';
        }

        $mode = PHP_ROUND_HALF_UP;
        $modeName = $this->get_arg($args, '$mode', null);
        if (is_string($modeName) && defined($modeName)) {
            $candidateMode = constant($modeName);
            $allowedModes = array(
                PHP_ROUND_HALF_UP,
                PHP_ROUND_HALF_DOWN,
                PHP_ROUND_HALF_EVEN,
                PHP_ROUND_HALF_ODD
            );
            if (in_array($candidateMode, $allowedModes, true)) {
                $mode = $candidateMode;
            }
        }

        return round(
            (float) $args['$num'],
            (int) $this->get_arg($args, '$precision', 0),
            $mode
        );
    }

    private function __mt_rand($args)
    {
        $hasMin = array_key_exists('$min', $args);
        $hasMax = array_key_exists('$max', $args);

        if (!$hasMin && !$hasMax) {
            return mt_rand();
        }

        if (!$hasMin || !$hasMax) {
            return '';
        }

        $min = (int) $args['$min'];
        $max = (int) $args['$max'];
        if ($max < $min) {
            return '';
        }

        return mt_rand($min, $max);
    }

    private function __pi($args)
    {
        return pi();
    }

    private function __pow($args)
    {
        if (!isset($args['$num'], $args['$exp'])) {
            return '';
        }
        return pow((float) $args['$num'], (float) $args['$exp']);
    }

    private function __sqrt($args)
    {
        if (!isset($args['$num'])) {
            return '';
        }
        $num = (float) $args['$num'];
        return $num < 0 ? '' : sqrt($num);
    }
}

class SyntaxException extends Exception
{
    public function errorMessage($syntax, $e = null)
    {
        if (!is_object($syntax) || !method_exists($syntax, 'get_command_list')) {
            return 'XtScript Error.';
        }

        $commands = $syntax->get_command_list();
        $line = method_exists($syntax, 'get_program_counter')
            ? max(0, (int) $syntax->get_program_counter() - 1)
            : 0;

        $source = isset($commands[$line]) ? $commands[$line] : '';
        return 'XtScript Error on line ' . ($line + 1) . ': <br />'
            . htmlspecialchars((string) $source, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
