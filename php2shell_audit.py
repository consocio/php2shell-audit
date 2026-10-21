#!/usr/bin/env python3
"""
php2shell-audit — rileva l'esposizione del TUO sito alle CVE-2026-109618/109619
secondo gli ADVISORY UFFICIALI php-src del 2026-10-21:
  CVE-2026-109618  RCE via OOM corruption      (GHSA-w8hw-w9fx-j79w)
  CVE-2026-109619  RCE via stale global state  (GHSA-6wmf-4rv5-p3rp)

USO AUTORIZZATO SOLO SU SITI DI TUA PROPRIETA' O CON PERMESSO ESPLICITO.

Comandi:
  remote   controlli remoti non invasivi (indicatori di esposizione)
  verify   verifica end-to-end con canary (richiede probe.php deployato)
  full     remote + verify + scansione docroot via probe

Esempi:
  python3 php2shell_audit.py remote --target https://www.miosito.it --authorize
  python3 php2shell_audit.py verify --target https://www.miosito.it/ \\
      --probe https://www.miosito.it/probe.php --secret SEGRETO --authorize
  python3 php2shell_audit.py full   --target https://www.miosito.it/ \\
      --probe https://www.miosito.it/probe.php --secret SEGRETO --authorize
"""

import argparse
import json
import re
import secrets
import socket
import ssl
import sys
from urllib.parse import urlparse, quote


# ---------------------------------------------------------------- HTTP ----

def _connect(url, timeout=20):
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        sys.exit(f"[!] Schema non supportato: {u.scheme}")
    tls = u.scheme == "https"
    host = u.hostname
    port = u.port or (443 if tls else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return host, port, path, tls

def http_get(url, headers=None, timeout=20):
    host, port, path, tls = _connect(url)
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: php2shell-audit/2.0\r\n"
        "Connection: close\r\n"
    )
    for k, v in (headers or {}).items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    s = socket.create_connection((host, port), timeout=timeout)
    if tls:
        s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
    s.sendall(req.encode("latin-1"))
    buf = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        buf += d
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    status = int(lines[0].split()[1]) if len(lines[0].split()) > 1 else 0
    hdrs = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            hdrs.setdefault(k.strip().lower(), []).append(v.strip())
    if "chunked" in hdrs.get("transfer-encoding", []):
        body = _dechunk(body)
    return status, hdrs, body

def _dechunk(data: bytes) -> bytes:
    out = b""
    while data:
        line, _, rest = data.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        data = rest[size + 2:]
    return out


def http_post_multipart(url, sid, filename, timeout=30):
    """POST multipart con PHPSESSID solo nel body + campo upload_progress.
    Replica il producer pre-RINIT del lifecycle upload_progress (CVE-2026-109619):
    filename innocuo, nessun codice eseguibile."""
    host, port, path, tls = _connect(url)
    boundary = "AUDIT" + secrets.token_hex(6)
    # escape delle virgolette nel filename come da primitiva rfc1867
    fn = filename.replace("\\", "\\\\").replace('"', '\\"')
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{fn}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    )
    s = socket.create_connection((host, port), timeout=timeout)
    if tls:
        s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
    s.sendall(head.encode("latin-1") + body)
    buf = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        buf += d
    s.close()
    head, _, _ = buf.partition(b"\r\n\r\n")
    status = int(head.decode("latin1").split("\r\n")[0].split()[1])
    return status


# ------------------------------------------------------------- HELPERS ----

def _on(v):
    return str(v).lower() in ("1", "on", "true", "yes")

def parse_php_size(v):
    """'8M'/'64M'/'1G'/'-1' -> MB (float) oppure None."""
    m = re.match(r"^(\d+)([KMG]?)$", str(v).strip())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2).upper()
    return {"": n / 1048576, "K": n / 1024, "M": float(n), "G": n * 1024}.get(unit)

def sapi_assessment(sapi):
    """Classificazione del rischio per SAPI secondo php.net / advisory."""
    s = (sapi or "").lower()
    if "apache2handler" in s:
        return ("RISCHIO MASSIMO: mod_php — RCE confermata pre-applicazione con "
                "limiti default (php.net: 'risk highest for mod_php')")
    if s in ("fpm-fcgi",):
        return ("ESPOSTO: FPM — il path dimostrato richiede un producer applicativo "
                "(fatal durante l'esecuzione) con upload_progress come consumer; "
                "il child esce sui fallimenti di startup, ma il path post-startup resta")
    if s in ("cgi-fcgi", "cgi"):
        return "ESPOSTO: CGI — nel gruppo a rischio dell'annuncio php.net"
    if "cli-server" in s:
        return "ESPOSTO: cli-server (lab: il child sopravvive al bailout)"
    if "litespeed" in s:
        return "PROBABILE: LSAPI — 'likely' per l'advisory, non validato"
    if "frankenphp" in s:
        return "PROBABILE: FrankenPHP — shutdown incondizionato, 'likely susceptible'"
    return f"SAPI non classificata ({sapi}): trattala come esposta finché non verifichi"

def mitigation_grade(ini):
    """Grading delle mitigazioni config indicate da php.net (perCVE)."""
    rows = []
    up = _on(ini.get("session.upload_progress.enabled"))
    rows.append(("session.upload_progress.enabled",
                 ini.get("session.upload_progress.enabled"),
                 "OK: chiude i path session della CVE-2026-109619 (riavvia i worker)"
                 if not up else
                 "DA DISATTIVARE: e' il consumer confermato della 619 (via php.ini/pool, NON ini_set o .user.ini)"))
    pms = parse_php_size(ini.get("post_max_size"))
    if pms is None:
        rows.append(("post_max_size", ini.get("post_max_size"), "valore non interpretabile"))
    elif pms <= 8:
        rows.append(("post_max_size", ini.get("post_max_size"), "OK: <= 8M come raccomandato senza upload"))
    elif pms <= 32:
        rows.append(("post_max_size", ini.get("post_max_size"), "ACCETTABILE: 8M senza upload / 32M se servono file upload"))
    else:
        rows.append(("post_max_size", ini.get("post_max_size"), "DA RIDURRE: > 32M amplia la superficie OOM della 618"))
    umf = parse_php_size(ini.get("upload_max_filesize"))
    if pms is not None and umf is not None and umf >= pms:
        rows.append(("upload_max_filesize", ini.get("upload_max_filesize"),
                     "DA CORREGGERE: tienilo sotto post_max_size"))
    rows.append(("max_input_vars", ini.get("max_input_vars"),
                 "OK" if int(ini.get("max_input_vars") or 0) <= 3000 else "DA RIDURRE (<=3000): riduce il costo del producer OOM 618"))
    rows.append(("max_input_nesting_level", ini.get("max_input_nesting_level"),
                 "OK" if int(ini.get("max_input_nesting_level") or 0) <= 32 else "DA RIDURRE (<=32): i nomi annidati moltiplicano il lavoro in memoria"))
    rows.append(("max_file_uploads", ini.get("max_file_uploads"),
                 "OK" if int(ini.get("max_file_uploads") or 0) <= 20 else "DA RIDURRE (<=20 se possibile)"))
    ml = str(ini.get("memory_limit", "")).strip()
    if ml == "-1":
        rows.append(("memory_limit", ml,
                     "OK (mitigazione primaria config della 618): conferma che NESSUN pool/dir/app ripristini un limite finito"))
    else:
        rows.append(("memory_limit", ml,
                     "LIMITATO: per la 618 la mitigazione config primaria e' memory_limit=-1 via php_admin_value "
                     "(solo su server gestiti con limiti esterni cgroup; MAI RLIMIT_AS/RLIMIT_DATA); su hosting condiviso non applicabile"))
    return rows


# ------------------------------------------------------------ CHECKS ----

def check_remote(target, path):
    print(f"\n=== CONTROLLI REMOTI: {target} ===")
    base = target.rstrip("/")
    findings = {}

    # 1. Pagina base: PHP rilevabile? Sessioni in uso?
    st, h, _ = http_get(base + path)
    xpb = ", ".join(h.get("x-powered-by", []))
    setc = "; ".join(h.get("set-cookie", []))
    php_detected = bool(xpb) or "PHPSESSID" in setc
    sessions_used = "PHPSESSID" in setc
    findings["php_detected"] = php_detected
    findings["sessions_used"] = sessions_used
    print(f"[1] PHP rilevabile (header): {'SI -> ' + xpb if xpb else 'no (headers puliti)'}")
    print(f"    Sessioni PHP (PHPSESSID cookie): {'in uso' if sessions_used else 'non rilevate su questa pagina'}")

    if not php_detected:
        print("    (PHP puo' essere comunque in uso: gli header non sono conclusivi)")

    # 2. Probe strict-mode: cookie con SID arbitrario viene accettato o rigenerato?
    probe_sid = secrets.token_hex(16)
    st2, h2, _ = http_get(base + path, headers={"Cookie": f"PHPSESSID={probe_sid}"})
    new_cookies = "; ".join(h2.get("set-cookie", []))
    regenerated = "PHPSESSID" in new_cookies and probe_sid not in new_cookies
    if sessions_used and not regenerated:
        print("[2] session.use_strict_mode: probabile OFF — il server accetta un SID")
        print("    arbitrario senza rigenerarlo (supporta il producer 619 con SID scelto)")
        findings["strict_mode_off"] = True
    elif regenerated:
        print("[2] session.use_strict_mode: probabile ON — SID sconosciuti rigenerati (buono)")
        findings["strict_mode_off"] = False
    else:
        print("[2] Impossibile determinare strict mode (pagina senza session_start?)")
        findings["strict_mode_off"] = None

    print("\nNota: i controlli remoti sono INDICATIVI. La verifica conclusiva richiede")
    print("      il probe (comando verify/full) o un controllo della configurazione.")
    return findings


def get_probe(probe_url, secret, action, **params):
    q = {"action": action, "token": secret, **params}
    st, _, b = http_get(probe_url + "?" + "&".join(f"{k}={quote(v)}" for k, v in q.items()))
    if st != 200:
        sys.exit(f"[!] Probe ha risposto {st}: controlla URL e --secret (probe deployato?)")
    try:
        return json.loads(b.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        sys.exit(f"[!] Risposta probe non JSON: {b[:200]!r}")

def cmd_verify(args):
    if not args.authorize:
        sys.exit("[!] Serve --authorize per confermare che sei autorizzato a testare il target.")
    if not args.probe or not args.secret:
        sys.exit("[!] verify richiede --probe e --secret (vedi probe.php).")

    # 1. Report di configurazione dal probe
    report = get_probe(args.probe, args.secret, "report")
    ini = report["ini"]
    ver = report["vulnerable_version"]
    up_raw = ini["session.upload_progress.enabled"]
    session_ext_ok = isinstance(up_raw, str) and up_raw != ""
    up = _on(up_raw) if session_ext_ok else False
    cleanup = _on(ini["session.upload_progress.cleanup"]) if session_ext_ok else False
    files_handler = str(ini["session.save_handler"]).lower() == "files"

    print(f"\n=== REPORT PROBE ===")
    print(f"PHP:        {report['php']} ({report['sapi']})")
    print(f"Versione:   {ver['note']}" + (" [VULNERABILE]" if ver["vulnerable"] else ""))
    for k, v in ini.items():
        print(f"  {k} = {v}")
    if not session_ext_ok:
        print("  [!] Le impostazioni session.* sono assenti: estensione session non caricata")
        print("      (build PHP --disable-all o senza ext/session): il producer/consumer")
        print("      upload_progress della 619 non esiste su questo runtime.")

    sapi_risk = sapi_assessment(report.get("sapi"))
    print(f"\nSAPI: {sapi_risk}")

    # 2. Canary (producer multipart pre-RINIT, filename innocuo)
    sid = secrets.token_hex(16)
    canary = f"AUDITCANARY-{secrets.token_hex(8)}"
    path = args.path or "/"
    st = http_post_multipart(args.target.rstrip("/") + path, sid, canary)
    print(f"\n[canary] POST multipart con SID nel body (producer 619) -> HTTP {st}")

    # canary con pipe: byte arbitrari del filename (solo testo, oggetto stdClass innocuo)
    sid2 = secrets.token_hex(16)
    pipe_canary = f'AUDITPIPE-{secrets.token_hex(8)}|O:8:"stdClass":0:{{}}'
    st2 = http_post_multipart(args.target.rstrip("/") + path, sid2, pipe_canary)
    print(f"[canary] POST con pipe+oggetto serializzato -> HTTP {st2}")

    # 3. Verifica sul file di sessione via probe
    f1 = get_probe(args.probe, args.secret, "file", sid=sid)
    f2 = get_probe(args.probe, args.secret, "file", sid=sid2)
    fixation = bool(f1.get("exists")) or bool(f2.get("exists"))
    canary_ok = bool(f1.get("exists")) and canary in f1.get("content", "")
    pipe_ok = bool(f2.get("exists")) and "O:8:" in f2.get("content", "") and "|" in f2.get("content", "")

    print(f"[probe]  file sess_{sid[:8]}...: {'creato' if f1.get('exists') else 'ASSENTE'}")
    print(f"[probe]  canary nel file: {'PRESENTE' if canary_ok else 'assente'}")
    print(f"[probe]  pipe+oggetto nel file: {'PRESENTE' if pipe_ok else 'assente'}")

    # 4. Scansione docroot (se richiesta) — superfici aggiuntive, NON parte
    #    degli advisory ufficiali (catene di terze parti non confermate)
    handlers, mismatch, lfi_sinks = set(), False, []
    if args.scan or args.mode == "full":
        scan = get_probe(args.probe, args.secret, "scan")
        handlers = {ini["session.serialize_handler"]}
        handlers |= {u["handler"] for u in scan.get("user_ini", [])}
        mismatch = len(handlers) > 1
        lfi_sinks = scan.get("lfi_sinks", [])
        unserialize_files = scan.get("unserialize", [])
        print(f"[scan]   serialize_handler distinti: {sorted(handlers)}"
              + ("  <- MISMATCH (esposizione residua, non parte degli advisory)" if mismatch else ""))
        print(f"[scan]   possibili sink LFI (include/require su input utente): "
              f"{len(lfi_sinks)} file")
        for p in lfi_sinks[:10]:
            print(f"           - {p}")
        print(f"[scan]   file con unserialize(): {len(unserialize_files)}")

    # 5. Grading mitigazioni config (riferimento: annuncio php.net 2026-10-21)
    print("\n=== MITIGAZIONI CONFIG (riferimento php.net 21/10/2026) ===")
    for key, val, note in mitigation_grade(ini):
        print(f"  {key} = {val}\n      {note}")
    print("  (non verificabile da qui: blocco multipart al fronte, limiti proxy su")
    print("   size decodificata/numero part/header, cgroup per worker)")

    # 6. Verdetto — modello advisory ufficiali
    print("\n" + "=" * 60)
    if not ver["vulnerable"]:
        print("VERDETTO: NON VULNERABILE — versione PHP patchata per entrambe le CVE.")
        print("Raccomandazione residua: valuta comunque upload_progress=Off come hardening")
        print("(php.net: 'prudent... as more attackers try to find flaws in this")
        print("hardly-used and hardly-tested feature').")
    else:
        eol = bool(ver.get("eol"))
        print("VERDETTO: VULNERABILE a entrambe le CVE (versione non fixata)." if not eol
              else "VERDETTO: VULNERABILE a entrambe le CVE — branch EOL, NESSUN fix ufficiale mai.")
        print()
        print("CVE-2026-109618 (OOM corruption): ESPOSTA su ogni SAPI web.")
        print(f"  SAPI rilevata: {sapi_risk}")
        print("  Mitigazioni config RIDUCONO ma NON chiudono (solo il patch e' completo):")
        print("  - memory_limit=-1 via php_admin_value (server gestiti, con cgroup; MAI")
        print("    RLIMIT_AS/RLIMIT_DATA) — su shared hosting non applicabile")
        print("  - post_max_size e limiti input come da grading sopra")
        print("  - limiti/blocco multipart al fronte, validi anche senza Content-Length")
        print()
        if not session_ext_ok:
            print("CVE-2026-109619 (stale global state): estensione session assente -> il path")
            print("  upload_progress NON esiste su questo runtime. Restano gli altri consumer")
            print("  (INI pre-init, error/extension state) se l'app o le estensioni li pubblicano.")
        elif not up:
            print("CVE-2026-109619 (stale global state): path SESSIONE chiusi (upload_progress off).")
            print("  Restano esposti: consumer INI pre-init (rimuovi direttive deprecate/valide")
            print("  male in .htaccess php_value / PHP_VALUE) e producer fatal-error dell'app.")
        else:
            print("CVE-2026-109619 (stale global state): path SESSIONE ATTIVI (upload_progress on).")
            if fixation:
                print("  CONFERMATO live: il parsing rfc1867 pre-app ha creato il file di sessione")
                print("  con il SID scelto — il consumer della 619 e' raggiungibile ora.")
            elif cleanup:
                print("  ATTENZIONE: cleanup=On svuota il file a fine upload: canary assente NON")
                print("  significa non vulnerabile — il ciclo resta sfruttabile in race.")
            else:
                print("  Canary non confermato (save_handler non 'files' o path senza multipart):")
                print("  tratta il path sessione come ATTIVO fintanto'che upload_progress e' on.")
            print("  Rimedio immediato: session.upload_progress.enabled=0 via php.ini/pool")
            print("  (NON ini_set / .user.ini) + riavvio di TUTTI i worker.")
        print()
        if eol:
            bp = ver.get("backport_branch", "")
            print(f"BRANCH EOL: nessun fix ufficiale. Opzioni: backport minimale del PHP team")
            print(f"  (github.com/php/php-src, branch {bp}) se compili da sorgente, pacchetti")
            print("  vendor distro/LTS (hanno ricevuto i patch in anticipo), oppure —")
            print("  l'unica soluzione completa — aggiornare a una branch supportata (8.2+).")
        else:
            print(f"FIX DISPONIBILE: aggiorna a {ver.get('fixed_in', '8.2.35+')} (o successiva della tua branch).")
        print("Aggiornare PHP resta l'unica soluzione completa per ENTRAMBE le CVE.")
    print("=" * 60)

def cmd_remote(args):
    if not args.authorize:
        sys.exit("[!] Serve --authorize per confermare che sei autorizzato a testare il target.")
    check_remote(args.target, args.path or "/")

def main():
    ap = argparse.ArgumentParser(
        description="Rileva esposizione CVE-2026-109618/109619 (advisory ufficiali php-src) su un sito tuo.",
        epilog="Solo per uso autorizzato su sistemi di tua proprieta'.",
    )
    sub = ap.add_subparsers(dest="mode", required=True)

    def common(p):
        p.add_argument("--target", required=True, help="URL base, es. https://www.miosito.it")
        p.add_argument("--path", default="/", help="path con sessioni attive (default /)")
        p.add_argument("--authorize", action="store_true",
                       help="dichiari di essere autorizzato a testare il target")

    p1 = sub.add_parser("remote", help="controlli remoti indicativi")
    common(p1)
    p1.set_defaults(func=cmd_remote)

    p2 = sub.add_parser("verify", help="verifica end-to-end via probe.php")
    common(p2)
    p2.add_argument("--probe", help="URL del probe.php deployato")
    p2.add_argument("--secret", help="token $SECRET impostato nel probe.php")
    p2.add_argument("--scan", action="store_true", help="scansiona anche la docroot via probe")
    p2.set_defaults(func=cmd_verify)

    p3 = sub.add_parser("full", help="remote + verify + scan")
    common(p3)
    p3.add_argument("--probe", required=True)
    p3.add_argument("--secret", required=True)
    p3.set_defaults(func=cmd_verify, scan=True)

    args = ap.parse_args()
    print("php2shell-audit 2.0 — CVE-2026-109618/109619 (advisory ufficiali php-src)")
    if args.mode in ("verify", "full"):
        if args.mode == "full":
            check_remote(args.target, args.path or "/")
        cmd_verify(args)
    else:
        args.func(args)


if __name__ == "__main__":
    main()
