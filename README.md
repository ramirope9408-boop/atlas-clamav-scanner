# ATLAS ClamAV Scanner

Dedicated fail-closed malware scanner for ATLAS.

Endpoints: `GET /health` and authenticated `POST /scan` (raw binary).

Railway variables:
- `ATLAS_SCAN_SECRET` (required, high entropy)
- `MAX_FILE_SIZE_MB=25` (optional)

Use `Authorization: Bearer <ATLAS_SCAN_SECRET>` for scans. Clamd listens only on loopback; uploaded bytes are not permanently stored.
