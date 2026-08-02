<?php

// Minimal standalone compatibility layer used by index.php/examples.
// Real XtGem deployments are expected to provide their own implementations.

class common
{
    public static function error_page($message = '', $site = null)
    {
        return true;
    }

    public static function get_param(&$param, $default = false, $valid_set = null)
    {
        if (!isset($param)) {
            return $default;
        }

        if (is_array($valid_set) && $valid_set !== [] && !in_array($param, $valid_set, true)) {
            return $default;
        }

        return $param;
    }

    /**
     * Parse the legacy "host/path?query" form used by XtScript.
     *
     * Return shape is kept compatible with the old helper after array_slice():
     * [subdomain-prefix, host, first-label, remaining-domain, path, query]
     */
    public static function domain($url)
    {
        $url = trim((string) $url);
        if ($url === '' || strlen($url) > 4096 || strpos($url, "\0") !== false) {
            return false;
        }

        if (preg_match('/[\x00-\x20\x7F]/', $url) === 1) {
            return false;
        }

        // This legacy helper accepts URLs without a scheme. Adding a dummy
        // scheme lets parse_url() split host/path/query safely.
        $parts = @parse_url('http://' . $url);
        if (!is_array($parts) || !isset($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['port'])) {
            return false;
        }

        $host = strtolower(rtrim((string) $parts['host'], '.'));
        if (!self::valid_host($host)) {
            return false;
        }

        $labels = explode('.', $host);
        if (count($labels) < 2) {
            return false;
        }

        $firstLabel = $labels[0];
        $remaining = implode('.', array_slice($labels, 1));
        $subdomainPrefix = count($labels) > 3
            ? implode('.', array_slice($labels, 0, -3))
            : '';
        $path = isset($parts['path']) ? (string) $parts['path'] : '';
        $query = isset($parts['query']) ? '?' . (string) $parts['query'] : '';

        return array($subdomainPrefix, $host, $firstLabel, $remaining, $path, $query);
    }

    public static function valid_host($host)
    {
        $host = (string) $host;
        if ($host === '' || strlen($host) > 253 || strpos($host, '..') !== false) {
            return false;
        }

        foreach (explode('.', $host) as $label) {
            if ($label === '' || strlen($label) > 63) {
                return false;
            }
            if (preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/iD', $label) !== 1) {
                return false;
            }
        }

        return true;
    }
}

class content_model
{
    public static function parse_xt($contents, $url, $info, &$widget_total = null, &$widget_placeholders = null)
    {
        return $contents;
    }
}

class X
{
    public static function model($model)
    {
        // The standalone shim only exposes the model XtScript actually needs.
        if ($model !== 'filesystem') {
            return false;
        }
        return new filesystem();
    }

    public static function get($var)
    {
        return $var;
    }
}

class filesystem
{
    private $user_dir;

    public function __construct()
    {
        $this->user_dir = realpath(__DIR__);
        if ($this->user_dir === false) {
            $this->user_dir = __DIR__;
        }
    }

    /**
     * Resolve an XtGem-style site URL to a standalone filesystem location.
     *
     * The bundled demo site (test.xtgem.com) is mapped to this project root.
     * Other hosts are isolated under ./sites/<host>/ and only resolve when
     * such a site root actually exists. Relative local paths intentionally
     * return false so script.php resolves them against the current site root.
     */
    public function path($url)
    {
        $url = trim((string) $url);
        if ($url === '' || strlen($url) > 4096 || strpos($url, "\0") !== false) {
            return false;
        }

        // Relative/local paths are not site identifiers. A bare *.xt is a
        // local XtScript file, not a hostname.
        $firstSlash = strpos($url, '/');
        if ($url[0] === '/'
            || ($firstSlash === false && strtolower(substr($url, -3)) === '.xt')
            || ($firstSlash !== false && strpos(substr($url, 0, $firstSlash), '.') === false)) {
            return false;
        }

        $parts = @parse_url('http://' . $url);
        if (!is_array($parts) || !isset($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['port'])) {
            return false;
        }

        $host = strtolower(rtrim((string) $parts['host'], '.'));
        if (!common::valid_host($host) || strpos($host, '.') === false) {
            return false;
        }

        $siteRoot = $host === 'test.xtgem.com'
            ? $this->user_dir
            : $this->user_dir . DIRECTORY_SEPARATOR . 'sites' . DIRECTORY_SEPARATOR . $host;

        $path = isset($parts['path']) ? rawurldecode((string) $parts['path']) : '';
        if (strpos($path, "\0") !== false || preg_match('/[\x00-\x1F\x7F]/', $path) === 1) {
            return false;
        }

        $segments = array();
        foreach (preg_split('~[\\\\/]+~', $path, -1, PREG_SPLIT_NO_EMPTY) as $segment) {
            if ($segment === '.' || $segment === '..') {
                return false;
            }
            if (strlen($segment) > 255) {
                return false;
            }
            $segments[] = $segment;
        }

        $relative = implode('/', $segments);
        $absolute = rtrim($siteRoot, '/\\');
        if ($relative !== '') {
            $absolute .= DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
        }

        return array(
            'subdomain' => $host,
            'absolute' => $absolute,
            'relative' => $relative,
        );
    }
}
