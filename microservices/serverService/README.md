# acm-server

`acm-server` is the only public-facing authentication service. The client
must call `/register`, `/login`, and `/whoami`; it must not call `acm-db`.

## Run

```sh
export INTERNAL_SERVICE_TOKEN='replace-with-the-same-long-random-secret'
export DB_ALLOWED_HOSTS='127.0.0.1,localhost'
export SESSION_COOKIE_SECURE='false' # local HTTP demo only
go run .
```

For real deployment, terminate HTTPS at a reverse proxy and leave
`SESSION_COOKIE_SECURE=true` (the default). Use a private network or firewall
to prevent public access to `acm-db`.

The server validates DNS-resolved database destinations against
`DB_ALLOWED_HOSTS`, uses bounded HTTP clients, limits request bodies, applies
per-client rate limits, hashes passwords with bcrypt, and stores only random
server-side session tokens in cookies.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `BIND_ADDRESS` | `127.0.0.1` | Listener address |
| `PORT` | `5002` | Listener port |
| `DNS_URL` | empty | DNS service URL |
| `SERVICE_ENDPOINT` | empty | Complete URL registered in DNS, for example `http://192.168.1.20:5002` |
| `CLIENT_ORIGIN` | `http://localhost:8080` | Exact browser origin allowed to use credentialed requests |
| `DB_URL` | empty | Optional allowlisted direct DB URL |
| `DB_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Allowed DB hostnames/IPs |
| `DB_PORT` | `5001` | Port appended to DNS destinations without a port |
| `INTERNAL_SERVICE_TOKEN` | none | Required shared secret for DB calls |
| `DNS_SERVICE_TOKEN` | empty | Optional shared token for an authenticated DNS service |
| `SESSION_COOKIE_SECURE` | `true` | Set false only for local HTTP testing |
