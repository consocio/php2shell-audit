<?php
/**
 * php2shell-audit probe — componente server-side per la verifica
 * delle CVE-2026-109618/109619 (advisory ufficiali php-src:
 * GHSA-w8hw-w9fx-j79w OOM corruption, GHSA-6wmf-4rv5-p3rp stale global state).
 *
 * USO: deploya questo file TEMPORANEAMENTE sul tuo server (docroot),
 * imposta $SECRET, esegui la verifica, poi CANCELLALO.
 * Non lasciarlo online: espone diagnostica di configurazione.
 */

$SECRET = 'CHANGE-ME-BEFORE-USE';

if (!isset($_GET['token']) || !hash_equals($SECRET, (string)$_GET['token'])) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'forbidden']);
    exit;
}
header('Content-Type: application/json');
$action = $_GET['action'] ?? 'report';

/**
 * Verdetto sulla versione PHP rispetto ai fix ufficiali
 * (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, rilasciati 2026-10-21).
 */
function version_verdict(string $v): array
{
    if (version_compare($v, '7.4.0', '<')) {
        return [
            'vulnerable' => true,
            'note' => 'PHP < 7.4: non coperto da backport ufficiali e fuori supporto da anni; tratta come vulnerabile e aggiorna',
        ];
    }
    if (version_compare($v, '8.2.0', '<')) {
        // 7.4 / 8.0 / 8.1: EOL, nessun fix dal progetto PHP,
        // backport minimali del security team + vendor distro/LTS.
        $branch = 'PHP-' . implode('.', array_slice(explode('.', $v), 0, 2))
                . '-CVE-2026-109618-109619';
        return [
            'vulnerable' => true,
            'eol' => true,
            'backport_branch' => $branch,
            'note' => "branch EOL: vulnerabile a ENTRAMBE le CVE, nessun fix ufficiale; backport minimali del PHP team (github.com/php/php-src, branch {$branch}) o pacchetti vendor distro/LTS; soluzione completa solo aggiornando a una branch supportata",
        ];
    }
    $fixed = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
    foreach ($fixed as $br => $fix) {
        if (version_compare($v, $br . '.0', '>=') && version_compare($v, $br . '.999', '<')) {
            $vuln = version_compare($v, $fix, '<');
            return [
                'vulnerable' => $vuln,
                'fixed_in' => $fix,
                'note' => $vuln ? "versione vulnerabile a ENTRAMBE le CVE, fix in $fix" : "patched ($fix o successiva)",
            ];
        }
    }
    return ['vulnerable' => false, 'note' => 'versione successiva ai fix noti: verifica gli advisory php-src'];
}

switch ($action) {
    case 'report':
        $ver = version_verdict(PHP_VERSION);
        echo json_encode([
            'php' => PHP_VERSION,
            'sapi' => php_sapi_name(),
            'os' => PHP_OS,
            'vulnerable_version' => $ver,
            'ini' => [
                // consumer/producer della 619 (session lifecycle pre-init)
                'session.upload_progress.enabled' => ini_get('session.upload_progress.enabled'),
                'session.upload_progress.cleanup' => ini_get('session.upload_progress.cleanup'),
                'session.upload_progress.prefix'  => ini_get('session.upload_progress.prefix'),
                'session.upload_progress.freq'    => ini_get('session.upload_progress.freq'),
                'session.upload_progress.min_freq' => ini_get('session.upload_progress.min_freq'),
                'session.use_only_cookies'        => ini_get('session.use_only_cookies'),
                'session.use_strict_mode'         => ini_get('session.use_strict_mode'),
                'session.save_handler'            => ini_get('session.save_handler'),
                'session.save_path'               => ini_get('session.save_path') ?: sys_get_temp_dir(),
                'session.serialize_handler'       => ini_get('session.serialize_handler'),
                // superficie OOM della 618 (mitigazioni config per advisory)
                'memory_limit'        => ini_get('memory_limit'),
                'post_max_size'        => ini_get('post_max_size'),
                'upload_max_filesize'  => ini_get('upload_max_filesize'),
                'max_file_uploads'     => ini_get('max_file_uploads'),
                'max_input_vars'       => ini_get('max_input_vars'),
                'max_input_nesting_level' => ini_get('max_input_nesting_level'),
                'max_input_time'       => ini_get('max_input_time'),
            ],
        ], JSON_PRETTY_PRINT);
        exit;

    case 'file':
        // Legge il file di sessione per un dato SID (solo [A-Za-z0-9_-])
        $sid = (string)($_GET['sid'] ?? '');
        if (!preg_match('/^[a-zA-Z0-9_-]{1,128}$/', $sid)) {
            echo json_encode(['error' => 'bad sid']);
            exit;
        }
        $dir = ini_get('session.save_path') ?: sys_get_temp_dir();
        $path = rtrim($dir, '/') . "/sess_$sid";
        if (!file_exists($path)) {
            echo json_encode(['exists' => false, 'path' => $path]);
            exit;
        }
        $c = (string)@file_get_contents($path);
        echo json_encode(['exists' => true, 'size' => strlen($c), 'content' => $c]);
        exit;

    case 'scan':
        // Scansiona la docroot del probe: .user.ini (handler), sink LFI, unserialize()
        $out = ['user_ini' => [], 'lfi_sinks' => [], 'unserialize' => []];
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator(__DIR__, FilesystemIterator::SKIP_DOTS)
            );
        } catch (Throwable $e) {
            echo json_encode(['error' => 'scan non avviabile: ' . $e->getMessage()]);
            exit;
        }
        $n = 0;
        foreach ($it as $f) {
            if (++$n > 5000) break; // limite di sicurezza
            try {
                $p = $f->getPathname();
                if ($f->getFilename() === '.user.ini') {
                    $h = (string)@file_get_contents($p);
                    if (preg_match('/serialize_handler\s*=\s*(\S+)/i', $h, $m)) {
                        $out['user_ini'][] = ['file' => $p, 'handler' => $m[1]];
                    }
                }
                if ($f->getExtension() === 'php' && $f->getSize() < 500000) {
                    $src = (string)@file_get_contents($p);
                    // rimuove i commenti prima del match (evita falsi positivi
                    // tipo "we require $_GET" nei commenti)
                    $src = preg_replace('!/\*.*?\*/!s', '', $src);
                    $src = preg_replace('!(^|\s)//[^\n]*!', '$1', $src);
                    $src = preg_replace('!^\s*#[^\n]*!m', '', $src);
                    if (preg_match('/(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)/i', $src)) {
                        $out['lfi_sinks'][] = $p;
                    }
                    if (preg_match('/unserialize\s*\(/i', $src)) {
                        $out['unserialize'][] = $p;
                    }
                }
            } catch (Throwable $e) {
                continue; // file/dir non leggibile (hosting condiviso): salta
            }
        }
        echo json_encode($out, JSON_PRETTY_PRINT);
        exit;

    default:
        echo json_encode(['error' => 'azione sconosciuta (report|file|scan)']);
}
