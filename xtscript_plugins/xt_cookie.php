<?php

class xt_cookie
{
    const XT_ALLOWED_METHODS = array('set', 'delete', 'get');
    const XT_ALLOW_ISOLATED = false;

    private static $url = false;
    private static $info = false;

    public static function __setup($url = false, $info = false)
    {
        self::$url = $url;
        self::$info = $info;
    }

    public static function set($args)
    {
        if (!is_array($args) || !isset($args['$name'], $args['$val']) || !self::request_domain_matches_context()) {
            return '';
        }

        $name = (string) $args['$name'];
        $value = self::scalar_string($args['$val']);
        if (!self::valid_name($name) || $value === null || strlen($value) > 4096) {
            return '';
        }

        $path = self::valid_path(isset($args['$path']) ? $args['$path'] : '/');
        if ($path === false) {
            return '';
        }

        $expire = self::expiry(isset($args['$expire']) ? $args['$expire'] : 0);
        if ($expire === false) {
            return '';
        }

        $domain = self::current_domain();
        $physicalName = $domain === false ? false : self::physical_name($name, $domain);
        if ($domain === false || $physicalName === false || headers_sent()) {
            return '';
        }

        try {
            $ok = setcookie($physicalName, $value, $expire, $path, $domain);
        } catch (Throwable $e) {
            return '';
        }

        if ($ok && self::truthy(isset($args['$force_current']) ? $args['$force_current'] : false)) {
            $_COOKIE[$physicalName] = $value;
        }

        return '';
    }

    public static function delete($args)
    {
        if (!is_array($args) || !isset($args['$name']) || !self::request_domain_matches_context()) {
            return '';
        }

        $name = (string) $args['$name'];
        if (!self::valid_name($name)) {
            return '';
        }

        // Fixed legacy typo: '$path' was read as 'path'.
        $path = self::valid_path(isset($args['$path']) ? $args['$path'] : '/');
        if ($path === false) {
            return '';
        }

        $domain = self::current_domain();
        $physicalName = $domain === false ? false : self::physical_name($name, $domain);
        if ($domain === false || $physicalName === false || headers_sent()) {
            return '';
        }

        try {
            $ok = setcookie($physicalName, '', time() - 86400, $path, $domain);
        } catch (Throwable $e) {
            return '';
        }

        if ($ok && self::truthy(isset($args['$force_current']) ? $args['$force_current'] : false)) {
            unset($_COOKIE[$physicalName]);
        }

        return '';
    }

    public static function get($args)
    {
        if (!is_array($args) || !isset($args['$name']) || !self::request_domain_matches_context()) {
            return '';
        }

        $name = (string) $args['$name'];
        if (!self::valid_name($name)) {
            return '';
        }

        $domain = self::current_domain();
        $physicalName = $domain === false ? false : self::physical_name($name, $domain);
        if ($physicalName === false) {
            return '';
        }

        if (isset($_COOKIE[$physicalName]) && is_scalar($_COOKIE[$physicalName])) {
            return (string) $_COOKIE[$physicalName];
        }

        if (array_key_exists('$default', $args)) {
            $default = self::scalar_string($args['$default']);
            return $default === null ? '' : $default;
        }

        return '';
    }

    private static function valid_name($name)
    {
        // PHP cookie names cannot contain separators/CTLs. Keep a conservative
        // subset to avoid header ambiguity and PHP 8 ValueError exceptions.
        return $name !== ''
            && strlen($name) <= 80
            && preg_match('/^[A-Za-z0-9!#$%&\'*+.^_`|~-]+$/D', $name) === 1;
    }

    private static function physical_name($logicalName, $domain)
    {
        if (!self::valid_name($logicalName) || !is_string($domain) || $domain === '') {
            return false;
        }

        // Never expose arbitrary request cookies to XtScript. The public API
        // keeps the logical name, while the browser cookie is isolated in a
        // deterministic per-domain namespace.
        $prefix = 'xts_' . substr(hash('sha256', strtolower($domain)), 0, 16) . '_';
        $physical = $prefix . $logicalName;
        return strlen($physical) <= 128 ? $physical : false;
    }

    private static function valid_path($path)
    {
        if (!is_scalar($path)) {
            return false;
        }
        $path = (string) $path;
        if ($path === '' || $path[0] !== '/' || strlen($path) > 1024) {
            return false;
        }
        if (preg_match('/[\x00-\x1F\x7F;,]/', $path) === 1) {
            return false;
        }
        return $path;
    }

    private static function expiry($seconds)
    {
        if ($seconds === '' || $seconds === null || $seconds === false || $seconds === 0 || $seconds === '0') {
            return 0;
        }
        if (!is_numeric($seconds)) {
            return false;
        }

        $seconds = (int) $seconds;
        // Bound attacker-controlled arithmetic and header lifetime to 10 years.
        if ($seconds < -315360000 || $seconds > 315360000) {
            return false;
        }

        $now = time();
        if ($seconds > 0 && $now > PHP_INT_MAX - $seconds) {
            return false;
        }
        if ($seconds < 0 && $now < PHP_INT_MIN - $seconds) {
            return false;
        }
        return $now + $seconds;
    }

    private static function request_domain_matches_context()
    {
        if (!isset($_SERVER['HTTP_HOST']) || $_SERVER['HTTP_HOST'] === '') {
            return true;
        }

        $requestHost = strtolower(trim((string) $_SERVER['HTTP_HOST']));
        if ($requestHost !== '' && $requestHost[0] === '[') {
            // IPv6 hosts are not supported as XtGem cookie domains.
            return false;
        }
        $colon = strrpos($requestHost, ':');
        if ($colon !== false && strpos($requestHost, ':') === $colon) {
            $requestHost = substr($requestHost, 0, $colon);
        }
        $requestHost = rtrim($requestHost, '.');

        $contextHost = self::current_domain();
        return $contextHost !== false && hash_equals($contextHost, $requestHost);
    }

    private static function current_domain()
    {
        $url = (string) self::$url;
        $host = explode('/', $url, 2)[0];
        $host = strtolower(rtrim($host, '.'));

        if ($host === '' || strlen($host) > 253 || strpos($host, '..') !== false) {
            return false;
        }
        foreach (explode('.', $host) as $label) {
            if ($label === '' || strlen($label) > 63
                || preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/iD', $label) !== 1) {
                return false;
            }
        }
        return $host;
    }

    private static function scalar_string($value)
    {
        if ($value === null || is_array($value) || is_object($value) || is_resource($value)) {
            return null;
        }
        if ($value === false) {
            return '';
        }
        if ($value === true) {
            return '1';
        }
        return (string) $value;
    }

    private static function truthy($value)
    {
        return !($value === false || $value === null || $value === '' || $value === 0 || $value === 0.0 || $value === '0');
    }
}
