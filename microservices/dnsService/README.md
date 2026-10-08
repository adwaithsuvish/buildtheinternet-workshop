# acm-dns

Fast, dependency-free Go service registry.

```sh
DNS_PORT=8053 go run .
```

`POST /register` accepts `{"domain":"acm-server"}` and stores the request
source IP. Services can send `X-Service-Endpoint: http://host:port` to
advertise a reachable endpoint without changing the OpenAPI contract.
`GET /lookup?domain=...` returns the registered destination or `404`.
