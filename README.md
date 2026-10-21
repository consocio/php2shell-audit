# php2shell-audit

Detects whether a PHP website is exposed to CVE-2026-109618/109619
according to the **official php-src advisories of 2026-10-21**:

- **CVE-2026-109618** — RCE via OOM corruption (GHSA-w8hw-w9fx-j79w)
- **CVE-2026-109619** — RCE via stale global state (GHSA-6wmf-4rv5-p3rp)

Both CVSS 9.2 Critical, pre-authentication. RCE was confirmed on Apache
mod_php with default limits; every PHP version below 8.2.35 (per branch:
< 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) is vulnerable. PHP 8.1 and older are
EOL: no official fix will ever ship for them; the PHP security team
published minimal source backports (branches
`PHP-7.4/8.0/8.1-CVE-2026-109618-109619`) and distro/LTS vendors received
the patches in advance.

For use on websites you **own** only, or with explicit authorization.

## How it works

Two components:

- **php2shell_audit.py** (client, Python 3 stdlib, zero dependencies)
- **probe.php** (server-side diagnostics that only the owner can deploy)

Three modes:

| Command | What it does | Reliability |
|---|---|---|
| `remote` | PHP/session detection via headers, use_strict_mode probe | indicative |
| `verify` | Configuration report from the probe + end-to-end canary | conclusive |
| `full` | remote + verify + docroot scan (.user.ini, LFI sinks, unserialize) | conclusive |

The verdict follows the advisory model:

- the **PHP version** is dispositive (it enters both CVEs regardless of
  anything else);
- the **SAPI** classifies the 618 risk (mod_php = highest: pre-app RCE
  confirmed; FPM = validated path with an application-level producer;
  CGI/LSAPI/FrankenPHP = exposed/likely);
- `session.upload_progress.enabled` is the confirmed 619 consumer: the
  canary (multipart POST with an SID in the body only, harmless filename)
  proves **live** that the pre-app rfc1867 producer runs and writes the
  session file;
- the tool **grades the configuration mitigations** recommended by
  php.net (upload_progress, post_max_size, max_input_vars/nesting_level,
  max_file_uploads, memory_limit) and prints what cannot be verified
  remotely (frontend multipart blocking, proxy limits, cgroups).

## Using it on your website

```bash
# 1. Remote checks only (no deployment needed)
python3 php2shell_audit.py remote --target https://www.example.com --authorize

# 2. Conclusive verification:
#    - copy probe.php into the docroot, set $SECRET inside probe.php
#    - run:
python3 php2shell_audit.py full \
    --target https://www.example.com/ \
    --probe https://www.example.com/probe.php \
    --secret YOUR-SECRET --authorize
#    - DELETE probe.php from the server
```

The probe is token-protected (`$SECRET`), exposes configuration
diagnostics only, and must be **removed after the audit**.

## Possible verdicts

- **NOT VULNERABLE** — patched PHP version (>= 8.2.35 / 8.3.36 / 8.4.27 /
  8.5.12). upload_progress=Off is still recommended as hardening.
- **VULNERABLE** — unpatched version. The tool details, per CVE:
  - 618: always exposed; SAPI risk classification + config mitigations
    that reduce but do not close (only updating is complete);
  - 619: session path ACTIVE (upload_progress on, producer confirmed by
    the canary) or CLOSED (upload_progress off: INI pre-init consumers
    and application fatal-error producers remain);
  - on EOL branches (<= 8.1): no official fix ever — PHP team minimal
    backport / vendor packages / branch upgrade, the only complete fix.
- **INCONCLUSIVE on 619-session** — upload_progress on but canary absent:
  cleanup=On wipes the data at the end of the upload (race exploitation
  remains possible), or save_handler is not `files` / save_path unreadable.
  Treat the path as active.

## Known limits

- `remote` cannot conclude anything without the probe.
- The docroot scan is a regex heuristic over additional surfaces
  (LFI/unserialize): NOT part of the official advisories; results are
  leads, not findings.
- The grading cannot see what requires server/proxy access: frontend
  multipart blocking, limits on decoded size/parts/headers, cgroups.
- If the runtime lacks the session extension (`--disable-all` builds),
  the tool says so explicitly: the 619 upload_progress path does not
  exist there, 618 remains.

## Remediation if vulnerable

Reference: php.net announcement 2026-10-21 + GHSA advisories. Only
updating is a complete fix.

```ini
; 619: closes the demonstrated session paths (NOT ini_set / .user.ini)
session.upload_progress.enabled = 0   ; then restart ALL workers

; 618: reduce the multipart/OOM vector (do not close it)
post_max_size = 8M                    ; 32M if file uploads are needed
max_input_vars = 3000
max_input_nesting_level = 32
max_file_uploads = 20
; memory_limit=-1 via php_admin_value ONLY on managed servers with
; external limits (per-worker cgroups; NEVER RLIMIT_AS/RLIMIT_DATA)
```

Plus, at the frontend: block/limit multipart POSTs towards paths that do
not use them, valid also for requests without Content-Length; remove
deprecated/invalid per-request PHP directives (.htaccess php_value,
PHP_VALUE to FPM); fix attacker-reachable fatal errors.

## Lab tests performed

Verified in the lab (isolated Lima VM, PHP 8.3.6 cli-server and an
8.2.34 `--disable-all` ASAN build):

- vulnerable version + upload_progress=1 -> VULNERABLE with canary+pipe
  landed in the session file and the 619 producer confirmed live
- upload_progress=0 -> verdict downgraded (session path closed) and NO
  session file created by the multipart POST (negative control)
- runtime without the session extension -> case flagged explicitly
- version map: 8.1.33/7.4.33 -> EOL + correct backport branch; 8.2.34 ->
  vulnerable, fix 8.2.35; 8.2.35/8.3.36/8.5.12 -> patched; < 7.4 ->
  vulnerable, not covered by official backports

---

# php2shell-audit (versione italiana)

Rileva se un sito PHP è esposto alle CVE-2026-109618/109619 secondo gli
**advisory ufficiali php-src del 2026-10-21**:

- **CVE-2026-109618** — RCE via OOM corruption (GHSA-w8hw-w9fx-j79w)
- **CVE-2026-109619** — RCE via stale global state (GHSA-6wmf-4rv5-p3rp)

Entrambe CVSS 9.2 Critical, pre-autenticazione. RCE confermata su Apache
mod_php con limiti di default; tutte le versioni PHP < 8.2.35 (per
branch: < 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) sono vulnerabili. PHP 8.1 e
precedenti sono EOL: nessun fix ufficiale mai; esistono i backport
minimali del PHP security team (branch `PHP-7.4/8.0/8.1-CVE-2026-109618-
109619`) e i pacchetti vendor distro/LTS (patch ricevuti in anticipo).

Solo per uso su siti di **tua proprietà** o con autorizzazione esplicita.

## Come funziona

Due componenti:

- **php2shell_audit.py** (client, Python 3 stdlib, zero dipendenze)
- **probe.php** (diagnostica server-side che solo il proprietario può
  deployare)

Tre modalità:

| Comando | Cosa fa | Affidabilità |
|---|---|---|
| `remote` | Detezione PHP/sessioni via header, probe di use_strict_mode | indicativa |
| `verify` | Report di configurazione dal probe + canary end-to-end | conclusiva |
| `full` | remote + verify + scansione docroot (.user.ini, sink LFI, unserialize) | conclusiva |

Il verdetto segue il modello degli advisory:

- la **versione** è dispositiva (entra nelle CVE-618/619 a prescindere
  dal resto);
- la **SAPI** classifica il rischio della 618 (mod_php = massimo: RCE
  pre-app confermata; FPM = path validato con producer applicativo;
  CGI/LSAPI/FrankenPHP = esposti/probabili);
- `session.upload_progress.enabled` è il consumer confermato della 619:
  il canary (POST multipart con SID solo nel body, filename innocuo)
  prova **live** che il producer rfc1867 pre-app gira e scrive il file
  di sessione;
- il tool fa il **grading delle mitigazioni config** indicate da php.net
  (upload_progress, post_max_size, max_input_vars/nesting_level,
  max_file_uploads, memory_limit) e stampa cosa resta non verificabile
  da remoto (blocco multipart al fronte, limiti proxy, cgroup).

## Uso sul tuo sito

```bash
# 1. Solo controlli remoti (nessun deploy necessario)
python3 php2shell_audit.py remote --target https://www.miosito.it --authorize

# 2. Verifica conclusiva:
#    - copia probe.php nella docroot, imposta $SECRET dentro probe.php
#    - esegui:
python3 php2shell_audit.py full \
    --target https://www.miosito.it/ \
    --probe https://www.miosito.it/probe.php \
    --secret IL-TUO-SEGRETO --authorize
#    - CANCELLA probe.php dal server
```

Il probe è protetto da token (`$SECRET`), espone solo diagnostica di
configurazione e va comunque **rimosso dopo l'audit**.

## Verdetti possibili

- **NON VULNERABILE** — versione PHP patchata (≥ 8.2.35 / 8.3.36 /
  8.4.27 / 8.5.12). Consigliato comunque upload_progress=Off come
  hardening.
- **VULNERABILE** — versione non patchata. Il tool dettaglia per CVE:
  - 618: sempre esposta; classificazione di rischio per SAPI +
    mitigazioni config che riducono ma non chiudono (solo il patch è
    completo);
  - 619: path sessione ATTIVI (upload_progress on, producer confermato
    dal canary) oppure CHIUSI (upload_progress off: restano i consumer
    INI pre-init e i producer fatal-error dell'app);
  - su branch EOL (≤ 8.1): nessun fix ufficiale — backport minimale
    PHP team / pacchetti vendor / upgrade di branch, l'unica soluzione
    completa.
- **INCONCLUSIVO su 619-session** — upload_progress on ma canary assente:
  cleanup=On cancella il dato a fine upload (sfruttamento in race resta
  possibile), oppure save_handler non `files` / save_path illeggibile.
  Tratta il path come attivo.

## Limiti noti

- `remote` non può confermare nulla di conclusivo senza il probe.
- La scansione docroot è un'euristica regex su superfici aggiuntive
  (LFI/unserialize): NON fa parte degli advisory ufficiali e i risultati
  vanno trattati come lead, non finding.
- Il grading non copre ciò che serve osservare lato server/proxy: blocco
  multipart al fronte, limiti su size decodificata/part/header, cgroup.
- Se il runtime non ha l'estensione session (build `--disable-all`), il
  tool lo segnala: il path upload_progress della 619 non esiste, la 618
  resta.

## Rimedio se vulnerabile

Riferimento: annuncio php.net 2026-10-21 + advisory GHSA. Solo
l'aggiornamento è la soluzione completa.

```ini
; 619: chiude i path session dimostrati (NON ini_set / .user.ini)
session.upload_progress.enabled = 0   ; poi riavviare TUTTI i worker

; 618: riducono il vettore multipart/OOM (non chiudono)
post_max_size = 8M                    ; 32M se servono file upload
max_input_vars = 3000
max_input_nesting_level = 32
max_file_uploads = 20
; memory_limit=-1 via php_admin_value SOLO su server gestiti con limiti
; esterni (cgroup per worker; MAI RLIMIT_AS/RLIMIT_DATA)
```

Più, al fronte: blocco/limiti dei POST multipart verso i path che non li
usano, validi anche per richieste senza Content-Length; rimozione di
direttive PHP deprecate/invalidhe applicate per-request (.htaccess
php_value, PHP_VALUE a FPM); fix dei fatal error raggiungibili da input.

## Test eseguiti

Verificato nel lab (VM Lima isolata, PHP 8.3.6 cli-server e build ASAN
8.2.34 --disable-all):

- versione vulnerabile + upload_progress=1 → VULNERABILE con canary+pipe
  nel file di sessione e producer 619 confermato live
- upload_progress=0 → verdetto declassato (path sessione chiusi) e nessun
  file di sessione creato dal POST multipart (negative control)
- runtime senza estensione session → caso segnalato esplicitamente
- mappa versioni: 8.1.33/7.4.33 → EOL+backport branch corretti; 8.2.34 →
  vuln fix 8.2.35; 8.2.35/8.3.36/8.5.12 → patched; < 7.4 → vulnerabile
