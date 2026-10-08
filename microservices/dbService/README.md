# acm-db

`acm-db` is an internal-only SQLite user storage service. It must never be
called by the browser or exposed directly to the public network.

## Run

```sh
export INTERNAL_SERVICE_TOKEN='replace-with-a-long-random-secret'
export DNS_URL='http://127.0.0.1:5000'
go run .
```

The default listener is `127.0.0.1:5001`. Set `BIND_ADDRESS` to a private
interface address only when the server runs on another host, and enforce a
firewall rule that permits port 5001 only from `acm-server`.

The database uses SQLite with WAL mode and a parameterized schema. The service
requires `X-Internal-Service-Token` on every endpoint and applies request-size,
timeout, and per-client rate limits.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `BIND_ADDRESS` | `127.0.0.1` | Private listener address |
| `PORT` | `5001` | Listener port |
| `DB_PATH` | `users.db` | SQLite file |
| `INTERNAL_SERVICE_TOKEN` | none | Required shared secret from `acm-server` |
| `DNS_URL` | empty | DNS service URL for registration |
| `DNS_SERVICE_TOKEN` | empty | Optional shared token for an authenticated DNS service |
| `SERVICE_ENDPOINT` | empty | Complete URL registered in DNS, for example `http://192.168.1.20:5001` |
