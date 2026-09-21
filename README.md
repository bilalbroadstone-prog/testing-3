# AIBOM Consumer Service

A **fully self-contained** service — no imports from any other project. It:

1. **Consumes** AIBOM scan packets from RabbitMQ.
2. **Processes** each packet locally — splits per-repo CycloneDX reports and
   extracts the embedded package CVEs, secrets, code (semgrep) findings and the
   component inventory directly from each report (no Grype, no MinIO).
3. **Dumps** to MongoDB — a per-scan `{ns}.sbom` record, granular
   `{ns}.sbom_report` vulnerability rows, and a daily-append `{ns}.ai_discovery`
   document.

## Layout

```
aibom_service/
├── run.py                    # entrypoint (RMQ mode, or --file test mode)
├── consumer.py               # RabbitMQ connection + consume loop
├── processing.py             # extraction, report building, daily-append merge, Mongo writes
├── db.py                     # MongoDB connection
├── config.py                 # loads .env, resolves cert paths
├── .env / .env.example
├── requirements.txt
├── log_scan_dispatcher.py    # hourly cron: publish due log-scan accounts to RMQ
├── deploy.sh                 # one-shot install as a systemd service
├── aibom-consumer.service    # systemd unit
├── logs/                     # rotating log file (LOG_FILE); gitignored
└── certs/
    ├── rmq/   (ca_certificate.pem, client_certificate.pem, client_key.pem)
    └── mongo/ (mongodb-ca.crt, mongodb.pem)
```

## Setup

```bash
cd aibom_service
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # edit values
# drop TLS files into certs/rmq and certs/mongo (see certs/README.md),
# or point the *_CERT paths in .env at existing absolute paths.
```

## Run

```bash
python run.py                       # consume from RabbitMQ continuously
python run.py --file packet.json    # test-process a saved packet (no RMQ)
python run.py --skip-checks         # skip startup cert/config validation
```

## Log-scan dispatcher (hourly cron)

`log_scan_dispatcher.py` is a standalone, run-to-completion script (not a daemon).
Each run it sweeps every namespace × asset, finds log-protected connector
accounts whose `log_next_scan` has passed, and publishes one small message per
due account to `LOG_SCAN_QUEUE` for a downstream scanner. It reuses this
service's Mongo connection and RabbitMQ TLS config. No decryption happens here
— the scanner decrypts credentials itself.

Each message contains exactly three plaintext fields:

```json
{"collection": "semp15.aws", "account_name": "soldierboy", "next_scan": 1783977600}
```

```bash
# Safe preview — find + log due accounts, publish nothing, change nothing:
python log_scan_dispatcher.py --dry-run
python log_scan_dispatcher.py --dry-run --namespace semp15   # scope to one org
python log_scan_dispatcher.py --dry-run --asset github       # scope to one asset

# Real run:
python log_scan_dispatcher.py
```

Relevant `.env` keys: `MONGO_USERS_DB`, `LOG_SCAN_QUEUE`, `EXCLUDED_NAMESPACES`,
`LOG_SCAN_ADVANCE_NEXT` (see `.env.example`).

- **`LOG_SCAN_ADVANCE_NEXT=true`** (default) makes the dispatcher advance each
  account's `log_next_scan` by `log_frequency` after publishing, so it isn't
  re-published next hour. Set `false` if the scanner updates it instead.
- A file lock (`.log_scan_dispatcher.lock`) prevents overlapping cron runs from
  double-dispatching.

Install the cron entry (as `cytex`, `crontab -e`) — runs at the top of every hour:

```cron
0 * * * * /home/cytex/aibom_service/venv/bin/python /home/cytex/aibom_service/log_scan_dispatcher.py >> /home/cytex/aibom_service/logs/log_scan_dispatcher.cron.log 2>&1
```

Logs go to `logs/log_scan_dispatcher.log` (rotating) plus the cron redirect above.

## Logging

Logs go to stdout (captured by systemd/journald) and, when `LOG_FILE` is set in
`.env`, to a rotating file as well:

```
LOG_FILE=logs/aibom_consumer.log   # relative to the service dir, or absolute
LOG_MAX_BYTES=10485760             # rotate at 10 MB
LOG_BACKUP_COUNT=5                 # keep 5 old files
```

```bash
tail -f logs/aibom_consumer.log        # the app's log file
journalctl -u aibom-consumer -f        # same output via journald (when run as a service)
```

## Deploy as a systemd service (CentOS / Linux)

Run the installer from the service directory — it creates the venv, installs
deps, installs the unit, and starts the service:

```bash
cd ~/aibom_service
./deploy.sh
```

The script is idempotent (safe to re-run after a code change — it reinstalls the
unit and restarts). It requires `sudo` to write the unit into
`/etc/systemd/system` and needs a valid `.env` (copied from `.env.example`) with
the correct cert paths already in place.

Manual equivalent / management:

```bash
sudo cp aibom-consumer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aibom-consumer   # start now + on boot

systemctl status aibom-consumer              # is it running?
sudo systemctl restart aibom-consumer        # after a code change
sudo systemctl stop aibom-consumer           # stop
```

> **SELinux (CentOS):** if the service won't start and `sudo ausearch -m avc -ts
> recent` shows denials, code under `/home` may be the cause. Test with `sudo
> setenforce 0`; if it then starts, add an SELinux policy or move the service
> dir to `/opt`.

## Data model written to MongoDB (`MONGO_DB`, default `data_asset`)

- **`{namespace}.sbom`** — one metadata record per repo scan
  (`sbom_name`, `source_repo`, `vuln`, `component_count`, `created_at`, …).
- **`{namespace}.sbom_report`** — one row per vulnerability finding.
- **`{namespace}.ai_discovery`** — **one document per day** (`scan_date` =
  midnight epoch). Each scan **appends** into it:
  - `packages` — vulnerable packages (rows merged by name, counts summed).
  - `inventory` — components grouped by type (merged by component id, occurrences summed).
  - `vuln_chart` — top packages by vuln count.
  - `secrets` — secret / AIBOM findings.
  - `code_findings` — semgrep summary (totals + severity counts).
  - `scan_times`, `repos` — per-day scan timestamps and contributing repos.

  Same key → one row with its value aggregated (no duplicate rows). `risk` and
  `compliance` sections, if ever added, are replace-only (kept latest).

## Behavior notes

- AMQP heartbeats (60s) let the broker reap the consumer if the process dies
  uncleanly, so newly published messages are never routed to a dead ("zombie")
  consumer and lost; a reconnect loop recovers real disconnects. Kernel TCP
  keepalive is added on Linux as defense-in-depth.
- Each message is `ack`ed on success, discarded (no requeue) on a permanent
  error (missing namespace / bad report), requeued on a transient error
  (e.g. a Mongo write failure).
- The day key is stored day-only (midnight epoch); individual scan times are in
  `scan_times`. New day → new document.
