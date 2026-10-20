# Cheethwari — private polling-site operations portal

**Scope:** one physical polling location, seven rooms (numbers 72–78), 19 wards, 6,831 listed voters in uploaded 2026 ward summaries. Aggregates are reference figures, not real-time voter turnout. No individual-level voted/not-voted data is stored.

## Implemented
- Hindi, responsive login and dashboard.
- Admin-created, individual password accounts; first-login password changes; cookie-based sessions, CSRF checks, session revocation, role and per-room reporting permissions.
- Seven room dashboards, 19 ward overview, admin-verified dhani directory.
- Operational issue reporting and resolution; near-live updates via WebSocket notifications and fresh API fetches.
- Official aggregate turnout report entry with source and timestamp (admin only).
- Auditing, account provisioning (including batches), disabling accounts, status/health endpoint.
- SQLite durable state with WAL; single backend worker and one Railway persistent volume.

## Local run
1. Install Python 3.12+, create virtualenv, install `pip install -r requirements.txt` (for tests: `pip install pytest httpx`).
2. Set environment `BOOTSTRAP_ADMIN_USERNAME=admin` and a *unique strong* `BOOTSTRAP_ADMIN_PASSWORD` with at least 16 characters. For local HTTP only set `COOKIE_SECURE=0` and `DATA_DIR=./.local_data`.
3. Run `uvicorn app:app --host 127.0.0.1 --port 8080 --workers 1`.
4. Open `http://127.0.0.1:8080`, sign in, change bootstrap password, create role-limited users. The bootstrap password is used only on first DB initialization.
5. Run `pytest -q`.

## Railway deployment (manual, requires a connected GitHub repository)
1. Create a PRIVATE GitHub repository and upload these files without `.env` or SQLite database files.
2. On Railway, create a private project, connect the repo to a service, enable deployments from its default branch; `railway.json` and Dockerfile are supplied.
3. Attach a persistent Railway volume to **`/data`** BEFORE first deployment. The server checks for a configured Railway volume and refuses to start without it.
4. Configure protected service variables: `BOOTSTRAP_ADMIN_USERNAME`, unique 20+ character `BOOTSTRAP_ADMIN_PASSWORD`, `DATA_DIR=/data`, `COOKIE_SECURE=1`.
5. Provision a Railway HTTPS domain, deploy and verify `/health` returns `{"ok":true,...}`. The login must work only over HTTPS in production.
6. Log in as admin and change bootstrap password. Create team accounts in the Admin section and distribute credentials individually over a private channel. Force team members to change passwords on first login.
7. Test with multiple accounts and physical handsets on the actual mobile networks. One host and one replica are required by the SQLite + in-process WebSocket design; horizontal scaling would require Redis/Postgres broadcasts.
8. Back up `/data/operations.sqlite3` using SQLite's backup API or consistent snapshot method. Verify restoration in a separate nonproduction environment. Do not copy only a live database file while WAL changes are pending.

## Safety and reliability notes
- **No election-day reliability guarantee** until production load/reconnect tests, HTTPS tests, backups, mobile-carrier checks and local electoral-rule review are complete.
- An authorized user can still photograph a screen. Restrict accounts and do not put personal voter records into this portal.
- Individual-level voting status (who voted, who has not) and political preference tracking are intentionally not implemented.
- Operational issues and official aggregate turnout reports are *not* evidence of any individual having voted.
- The `qa/load-test.json` figures reflect a single-host loopback test of 100 live WebSockets, not independent mobile devices or a production SLA.
- **Fallback:** maintain printed booth-room contact sheets and a phone chain for service/network downtime; use the official election authority's reporting process.
- Service environment secrets must never be committed to Git or distributed to team members.

## Remaining to become live
A private GitHub repository linked to the Railway account, hosting/volume/domain setup, production security review, and real-device rehearsal. This ZIP is a source package, **not** a deployed site.
