# acm-app

Fast, dependency-free Go web client with an embedded, responsive interface.

```sh
APP_PORT=8080 go run .
```

Open `http://localhost:8080`, enter the DNS service address and authentication
server port, and start the flow. The browser performs DNS lookup, login,
registration fallback for a new user, retry login, and `/whoami`, while showing
each event live. Requests have a six-second timeout so failed services provide
quick feedback.
