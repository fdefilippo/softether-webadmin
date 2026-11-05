# softether-webadmin — Tappa 1: fondamenta e primo accesso — Piano di implementazione

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un demone Go installabile come pacchetto. Su un vpnserver appena installato
guida il primo accesso con un token monouso, imposta la password di amministrazione,
permette il login dell'amministratore del server e mostra una panoramica del server.
Tutto questo con le protezioni di sicurezza del design (isolamento `adminip.txt`,
impronta TLS fissata, CSRF, `no-store`, CSP).

**Architecture:** Un solo binario statico (`CGO_ENABLED=0`) con template, CSS e htmx
incorporati. È organizzato in package interni: configurazione, trasporto JSON-RPC con
impronta fissata, sonda dello stato del server, `adminip.txt`, token di primo accesso,
web (sessioni, sicurezza, i18n, handler), audit. In questa tappa il client JSON-RPC
tipizzato copre solo i 4 metodi necessari. Il generatore del client completo è il
primo compito della tappa 2.

**Tech Stack:** Go 1.27.3 (`go 1.27.3` in `go.mod`; in CI `actions/setup-go` con `go-version-file: go.mod`),
`net/http` e `html/template` della libreria standard, htmx 2.0.4 (file incorporato),
`github.com/BurntSushi/toml` per la configurazione, nfpm per i pacchetti deb/rpm,
GitHub Actions. Test di integrazione su `docker.io/softethervpn/vpnserver:5.2.5189`.

**Spec:** `docs/superpowers/specs/2026-11-05-softether-webadmin-design.md` (rev. 2, approvata)

## Global Constraints

- Modulo Go: `github.com/fdefilippo/softether-webadmin`, `go 1.27.3`. Licenza Apache-2.0 (file `LICENSE`).
- Nessuna dipendenza oltre la libreria standard e `github.com/BurntSushi/toml`.
  Niente Node/npm, niente generatori di template.
- Mai scrivere su disco o nei log password SoftEther o parametri sensibili. Le
  credenziali stanno solo nella sessione in memoria.
- Lingue: inglese (`en`, predefinita) e italiano (`it`). Nessun testo visibile
  all'utente fuori dai cataloghi. L'italiano usa la terminologia di `strtable_it.stb`
  (Hub virtuale, amministratore del server, ecc.).
- Header su **tutte** le risposte autenticate e su tutti i frammenti htmx:
  `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, e
  `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'`.
- Cookie di sessione `swa_session`: `HttpOnly; Secure; SameSite=Strict; Path=/`.
  Scadenza per inattività 30 min, scadenza assoluta 8 h.
- Config di htmx (meta `htmx-config`): `allowEval:false`, `allowScriptTags:false`,
  `historyCacheSize:0`, `refreshOnHistoryMiss:true`, `includeIndicatorStyles:false`,
  `selfRequestsOnly:true`.
- Sonda: metodo `Test` con nome utente vuoto e password casuale di 32 byte
  (hex). Intervallo 60 s.
- **Mai ripetere automaticamente una scrittura JSON-RPC.**
- Percorsi predefiniti:
  - configurazione: `/etc/softether-webadmin/config.toml`;
  - stato: `/var/lib/softether-webadmin` (impronta in `server-cert.sha256`,
    certificato HTTPS in `tls/cert.pem` e `tls/key.pem`);
  - runtime: `/run/softether-webadmin` (token in `setup-token`, `0600`);
  - `adminip.txt`: `/var/lib/softether/adminip.txt`;
  - JSON-RPC: `https://127.0.0.1:5555/api/`;
  - ascolto: `127.0.0.1:9443`.
- **Decisione del piano: il servizio gira come `root`, fortemente isolato da systemd.**
  Serve per leggere e, solo con l'azione esplicita, riscrivere `adminip.txt` in
  `/var/lib/softether` (`0700 root`). Isolamento: `ProtectSystem=strict`, scrittura
  consentita solo su `/var/lib/softether-webadmin`, `/run/softether-webadmin` e
  `-/var/lib/softether`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`.
- Fuori da questa tappa, nella tappa 2: generatore del client completo, rotazione del certificato da interfaccia (design 5.3), operazioni che possono interrompere il collegamento oltre al primo accesso (5.4), lettura-modifica-riscrittura serializzata (5.5).
- Login in questa tappa: solo l'amministratore del server (nome utente vuoto). Il
  ruolo di amministratore di Hub arriva nella tappa 2.

## Review Focus

1. `adminip.txt` con commenti `#`/`//`, righe vuote, CRLF, BOM UTF-8, indirizzi senza
   maschera (`127.0.0.1`), `127.0.0.0/8`, `::1`. Deve classificare correttamente come
   loopback, e marcare come non isolato qualunque voce non di loopback, anche dentro
   una riga con il nome di un Hub. Test nel Task 4.
2. vpnserver che si ferma o riparte mentre il demone è attivo. Le pagine mostrano
   "server irraggiungibile" senza crash, la sessione resta valida, e al ritorno del
   server tutto riprende. Test nel Task 7.
3. Password con `:`, spazi e caratteri non ASCII (per esempio `pa:ss è`) nel login e
   nella configurazione iniziale. L'header Basic deve essere corretto. Test nel Task 2.
4. Tasto Indietro del browser o URL riaperto dopo il logout. Con `no-store` e la
   sessione distrutta, si viene reindirizzati al login e non si vedono dati. Test nel
   Task 6.
5. Demone riavviato mentre la password è ancora vuota, con il vecchio file del token
   presente. Viene generato un token nuovo e il vecchio non funziona più. Test nel
   Task 5.

---

### Task 1: Scheletro del progetto e configurazione

**Files:**
- Create: `go.mod` (`module github.com/fdefilippo/softether-webadmin`, `go 1.27.3`), `LICENSE` (Apache-2.0), `README.md` (breve, in inglese: cos'è, stato "work in progress", link al design)
- Create: `cmd/softether-webadmin/main.go`
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces:
  - `type Config struct { Listen, TLSCert, TLSKey, SoftEtherURL, AdminIPPath, StateDir, RuntimeDir string; SessionIdle, SessionMax, ProbeInterval time.Duration; LoginMaxFailures int; LoginWindow time.Duration }`
  - `func Default() Config` con i valori dei Global Constraints più `SessionIdle=30m`,
    `SessionMax=8h`, `ProbeInterval=60s`, `LoginMaxFailures=5`, `LoginWindow=15m`.
  - `func Load(path string) (Config, error)`: TOML con chiavi snake_case (`listen`,
    `tls_cert`, `tls_key`, `softether_url`, `adminip_path`, `state_dir`, `runtime_dir`,
    `session_idle`, `session_max`, `probe_interval`, `login_max_failures`,
    `login_window`). Le durate sono stringhe Go (`"30m"`). Le chiavi assenti tengono il
    default; un file inesistente è un errore; le chiavi sconosciute sono un errore.
  - `main.go`: sottocomandi `serve` (predefinito), `setup-token`, `trust-server-cert`,
    `version`, tutti con il flag `--config` (default `/etc/softether-webadmin/config.toml`).
    In questo task `serve`, `setup-token` e `trust-server-cert` stampano "not
    implemented" ed escono con 2; `version` stampa `softether-webadmin <version>`
    (variabile `version` impostata con `-ldflags`, default `dev`).

- [ ] **Step 1: Scrivere i test**
  - `TestDefault`: `Default().Listen == "127.0.0.1:9443"`, `SoftEtherURL == "https://127.0.0.1:5555/api/"`, `ProbeInterval == 60*time.Second`.
  - `TestLoadOverridesAndKeepsDefaults`: file con solo `listen = "10.0.0.5:9443"` e `session_idle = "10m"`, quindi `Listen` e `SessionIdle` cambiati e `AdminIPPath == "/var/lib/softether/adminip.txt"`.
  - `TestLoadUnknownKey`: `foo = 1` dà un errore che contiene `foo`.
  - `TestLoadMissingFile`: errore.
- [ ] **Step 2: Eseguire `go test ./internal/config/...`**: deve FALLIRE (package inesistente).
- [ ] **Step 3: Implementare `Default`, `Load` e lo scheletro di `main.go`.** Per le chiavi sconosciute usare `toml.MetaData.Undecoded()`.
- [ ] **Step 4: Eseguire `go test ./... && go vet ./... && go run ./cmd/softether-webadmin version`**: test PASS, l'ultimo comando stampa `softether-webadmin dev`.
- [ ] **Step 5: Commit** `feat: project skeleton and configuration`

### Task 2: Trasporto JSON-RPC con impronta TLS fissata

**Files:**
- Create: `internal/rpc/client.go`, `internal/rpc/pin.go`, `internal/rpc/errors.go`
- Test: `internal/rpc/client_test.go`, `internal/rpc/pin_test.go`

**Interfaces:**
- Consumes: niente.
- Produces:
  - `type Credential struct { Username, Password string }` (`Username` vuoto = amministratore del server).
  - `type PinStore struct { Path string }`, `func (p PinStore) Load() (string, bool, error)`
    (impronta in hex minuscolo, `false` se il file manca), `func (p PinStore) Save(fp string) error`
    (scrittura atomica, file `0600`).
  - `func Fingerprint(certDER []byte) string`: SHA-256 in hex minuscolo.
  - `type Client struct{ ... }`, `func NewClient(baseURL string, pins PinStore, allowTOFU bool) *Client`.
  - `func (c *Client) Call(ctx context.Context, cred Credential, method string, params, result any) error`:
    POST di `{"jsonrpc":"2.0","id":"<n>","method":method,"params":params}` con header
    `Authorization: Basic base64(username ":" password)` (byte UTF-8 grezzi) e
    `Content-Type: application/json`. Decodifica `result` nell'oggetto passato.
  - `func (c *Client) ObservedFingerprint() string`: l'impronta dell'ultimo certificato visto.
  - Errori:
    - `var ErrUnauthorized` per HTTP 401;
    - `var ErrUnreachable`, che avvolge gli errori di rete e di timeout;
    - `type CertMismatchError struct{ Pinned, Presented string }`;
    - `type APIError struct{ Code int; Message string }` per il campo `error` della JSON-RPC.
  - Verifica del certificato con `tls.Config{InsecureSkipVerify: true, VerifyConnection: ...}`:
    - con impronta salvata: confronto, e `CertMismatchError` se diversa (le credenziali
      non vengono mai inviate);
    - senza impronta e con `allowTOFU`: salvataggio dell'impronta presentata;
    - senza impronta e senza `allowTOFU`: `CertMismatchError{Pinned:""}`.
  - Timeout di ogni chiamata: 15 s. **Nessun nuovo tentativo.**

- [ ] **Step 1: Scrivere i test** con `httptest.NewTLSServer` che imita `/api/`:
  - `TestCallSendsBasicAuthAndEnvelope`: il server registra l'header. Con
    `Credential{"", "pa:ss è"}` deve arrivare esattamente
    `Basic ` + base64(`":pa:ss è"` in UTF-8); il corpo ha `method:"Test"`.
  - `TestCall401`: il server risponde 401, quindi `errors.Is(err, ErrUnauthorized)`.
  - `TestCallAPIError`: corpo `{"error":{"code":52,"message":"Not enough privileges."}}`, quindi `*APIError` con `Code == 52`.
  - `TestCallUnreachable`: URL verso una porta chiusa, quindi `errors.Is(err, ErrUnreachable)`.
  - `TestTOFUSavesPinThenMismatch`: la prima chiamata con `allowTOFU=true` salva il pin
    uguale a `Fingerprint(server.Certificate().Raw)`. Poi si sovrascrive il pin con
    `"00"*32`: la chiamata successiva dà `*CertMismatchError` e il server **non** riceve
    la richiesta (contatore delle richieste invariato).
  - `TestNoTOFUWithoutPin`: con `allowTOFU=false` e senza pin si ottiene `*CertMismatchError` con `Pinned == ""`.
- [ ] **Step 2: Eseguire `go test ./internal/rpc/...`**: deve FALLIRE.
- [ ] **Step 3: Implementare** `client.go`, `pin.go` ed `errors.go` secondo le Interfaces.
- [ ] **Step 4: Eseguire `go test -race ./internal/rpc/...`**: PASS.
- [ ] **Step 5: Commit** `feat(rpc): JSON-RPC transport with pinned server certificate`

### Task 3: Metodi tipizzati minimi e sonda dello stato

**Files:**
- Create: `internal/rpc/methods.go`, `internal/softether/probe.go`
- Create: `internal/rpc/rpctest/fakeserver.go` (finto vpnserver riusabile nei test)
- Test: `internal/softether/probe_test.go`, `internal/rpc/methods_test.go`

**Interfaces:**
- Consumes: `rpc.Client`, `rpc.Credential` e gli errori del Task 2.
- Produces:
  - `type ServerInfo struct { ProductName string \`json:"ServerProductName_str"\`; Version string \`json:"ServerVersionString_str"\`; Build string \`json:"ServerBuildInfoString_str"\`; Hostname string \`json:"ServerHostName_str"\`; ServerType uint32 \`json:"ServerType_u32"\`; OsName string \`json:"OsProductName_str"\` }`
  - `type ServerStatus struct { NumSessions uint32 \`json:"NumSessionsTotal_u32"\`; NumHubs uint32 \`json:"NumHubTotal_u32"\`; StartTime string \`json:"StartTime_dt"\`; CurrentTime string \`json:"CurrentTime_dt"\` }`
  - `func (c *Client) Test(ctx, cred) error`, `GetServerInfo(ctx, cred) (ServerInfo, error)`,
    `GetServerStatus(ctx, cred) (ServerStatus, error)`,
    `SetServerPassword(ctx, cred, newPassword string) error` (parametro `PlainTextPassword_str`).
  - `rpctest.FakeServer`: `New(t) *FakeServer` (TLS) con `SetPassword(string)`,
    `Stop()`, `Start()`, `Requests() int`, `URL() string`, `Cert() *x509.Certificate`.
    Imita il comportamento di SoftEther: con password vuota accetta qualunque
    credenziale; altrimenti accetta solo il nome utente `""` o `administrator` con la
    password giusta, e risponde 401 negli altri casi. Implementa `Test`,
    `GetServerInfo`, `GetServerStatus`, `SetServerPassword`.
  - `type State int` con le costanti `StateEmptyPassword`, `StatePasswordSet`,
    `StateUnreachable`, `StateCertMismatch`.
  - `type Prober struct{ Client *rpc.Client }`, `func (p Prober) Probe(ctx) (State, error)`:
    chiama `Test` con `Credential{"", <32 byte casuali in hex>}`:
    - successo dà `StateEmptyPassword`;
    - `ErrUnauthorized` dà `StatePasswordSet`;
    - `ErrUnreachable` dà `StateUnreachable`;
    - `*CertMismatchError` dà `StateCertMismatch` (l'errore viene restituito);
    - qualunque altro errore viene restituito con `StateUnreachable`.

- [ ] **Step 1: Scrivere i test**
  - `TestProbeEmptyPassword`: il FakeServer senza password dà `StateEmptyPassword`.
  - `TestProbePasswordSet`: con `SetPassword("x")` si ottiene `StatePasswordSet`.
  - `TestProbeUnreachable`: con `Stop()` si ottiene `StateUnreachable`.
  - `TestProbeCertMismatch`: con il pin errato si ottiene `StateCertMismatch`.
  - `TestSetServerPasswordThenProbe`: `SetServerPassword` porta lo stato da `StateEmptyPassword` a `StatePasswordSet`.
  - `TestGetServerInfoDecodes`: `Version` non vuoto.
- [ ] **Step 2: Eseguire `go test ./internal/...`**: deve FALLIRE.
- [ ] **Step 3: Implementare** `methods.go`, `probe.go` e `rpctest/fakeserver.go`.
- [ ] **Step 4: Eseguire `go test -race ./internal/...`**: PASS.
- [ ] **Step 5: Commit** `feat: typed bootstrap methods and server state probe`

### Task 4: Classificazione di `adminip.txt` e azione "limita a loopback"

**Files:**
- Create: `internal/softether/adminip.go`
- Test: `internal/softether/adminip_test.go`

**Interfaces:**
- Produces:
  - `type Isolation struct { Missing bool; Isolated bool; Offending []string }`:
    `Isolated` vale true solo se il file esiste e tutte le voci valide sono di loopback;
    `Offending` contiene le righe originali (senza commenti) non di loopback o non
    analizzabili.
  - `func ClassifyAdminIP(path string) (Isolation, error)`. Supporta BOM UTF-8, CRLF,
    commenti `#` e `//` (anche a fine riga), separatori spazio e tab. Il primo token è
    l'IP, con o senza `/maschera` (maschera decimale o lunghezza del prefisso),
    IPv4 o IPv6; un secondo token opzionale è il nome dell'Hub. Il loopback è
    `127.0.0.0/8` o `::1/128`, e la rete della voce deve stare interamente nel loopback.
  - `func RestrictToLoopback(path string, now time.Time) (backup string, err error)`:
    se il file esiste lo copia in `<path>.bak-<YYYYmmdd-HHMMSS>`, poi scrive con
    file temporaneo e rename (`0600`):
    ```
    # Restricted to loopback by softether-webadmin on <RFC3339>
    127.0.0.1/32
    ::1/128
    ```

- [ ] **Step 1: Scrivere i test**, come tabella con i file in `t.TempDir()`:
  - file assente: `Missing:true, Isolated:false`;
  - `"127.0.0.1/32\r\n::1/128\r\n"`: isolato;
  - BOM + `"# c\n\n127.0.0.1 // locale\n"`: isolato;
  - `"127.0.0.0/8\n"`: isolato;
  - `"127.0.0.1/32\n192.168.1.0/24 HUB1\n"`: non isolato, `Offending == ["192.168.1.0/24 HUB1"]`;
  - `"0.0.0.0/0\n"`: non isolato;
  - `"127.0.0.1/0\n"`: non isolato (la maschera esce dal loopback);
  - `"spazzatura\n"`: non isolato, con la riga in `Offending`;
  - `TestRestrictToLoopback`: crea il backup con il contenuto originale, il nuovo file
    è classificato isolato e ha permessi `0600`.
- [ ] **Step 2: Eseguire `go test ./internal/softether/...`**: deve FALLIRE.
- [ ] **Step 3: Implementare** con `net/netip` (`netip.ParsePrefix`/`ParseAddr`; per la maschera decimale convertire in lunghezza del prefisso).
- [ ] **Step 4: Eseguire `go test ./internal/softether/...`**: PASS.
- [ ] **Step 5: Commit** `feat: adminip.txt isolation check and restrict-to-loopback`

### Task 5: Token di primo accesso

**Files:**
- Create: `internal/setup/token.go`
- Test: `internal/setup/token_test.go`

**Interfaces:**
- Consumes: `softether.Prober`/`State` (Task 3), `rpc.Client.SetServerPassword` (Task 3).
- Produces:
  - `type Manager struct{ ... }`, `func NewManager(runtimeDir string, client *rpc.Client, prober softether.Prober, logger *slog.Logger) *Manager`.
  - `func (m *Manager) Refresh(ctx, state softether.State) error`:
    - con `StateEmptyPassword` e nessun token valido in memoria, genera un token
      (32 byte casuali, base32 senza padding) e lo scrive in `<runtimeDir>/setup-token`
      (`0600`, scrittura atomica). Nel journal scrive
      `level=WARN msg="setup token generated" token=<token>`; è l'unico log che contiene
      il token;
    - con `StatePasswordSet`, invalida il token e cancella il file;
    - con gli altri stati non fa nulla.
  - `func (m *Manager) Active() bool`.
  - `func (m *Manager) Complete(ctx, token, newPassword string) error`, sotto un mutex,
    nell'ordine:
    1. confronto del token in tempo costante; se errato, `ErrBadToken`;
    2. sonda, che deve dare `StateEmptyPassword`, altrimenti `ErrAlreadyConfigured`;
    3. `SetServerPassword` con `Credential{"", ""}`;
    4. sonda, che deve dare `StatePasswordSet`, altrimenti `ErrUncertain`;
    5. invalidazione del token e cancellazione del file.

    Se il passo 3 dà un errore di trasporto, si salta alla sonda del passo 4: se il
    risultato è `StatePasswordSet` è un successo, altrimenti `ErrUncertain`. **Nessun
    nuovo tentativo.**
  - Errori esportati: `ErrBadToken`, `ErrAlreadyConfigured`, `ErrUncertain`, `ErrNoToken`.
  - `func ReadTokenFile(runtimeDir string) (string, error)`, usato dal sottocomando `setup-token`.
  - Requisito della password: almeno 12 caratteri, altrimenti `ErrWeakPassword`. È un
    valore scelto dal piano; il messaggio è nei cataloghi.

- [ ] **Step 1: Scrivere i test** con `rpctest.FakeServer`:
  - `TestRefreshGeneratesTokenFile`: si crea il file `0600` con lo stesso token di `Active()`.
  - `TestCompleteHappyPath`: con il token giusto la password viene impostata, il file
    viene cancellato e `Active()==false`.
  - `TestCompleteBadToken`: `ErrBadToken`, e la password del server resta vuota.
  - `TestCompleteConcurrent`: due goroutine con lo stesso token: esattamente una
    riesce, l'altra riceve `ErrAlreadyConfigured` oppure `ErrNoToken`.
  - `TestExternalPasswordSetInvalidates`: `FakeServer.SetPassword("x")` seguito da `Refresh(StatePasswordSet)` porta `Active()` a false e cancella il file.
  - `TestRestartReplacesStaleToken` (Review Focus 5): si scrive un token vecchio nel
    file, si crea un nuovo `Manager` e si chiama `Refresh(StateEmptyPassword)`. Il file
    contiene un token diverso e `Complete` con il vecchio dà `ErrBadToken`.
  - `TestCompleteUncertain`: il FakeServer viene fermato durante `SetServerPassword`
    (hook nel fake), quindi `ErrUncertain`.
- [ ] **Step 2: Eseguire `go test ./internal/setup/...`**: deve FALLIRE.
- [ ] **Step 3: Implementare** `token.go`. Per aggiungere al FakeServer l'hook "si ferma dopo aver ricevuto il metodo X", estendere `rpctest`.
- [ ] **Step 4: Eseguire `go test -race ./internal/setup/...`**: PASS.
- [ ] **Step 5: Commit** `feat(setup): one-time setup token with atomic completion`

### Task 6: Fondamenta web (sessioni, sicurezza, i18n, layout)

**Files:**
- Create: `internal/web/session.go`, `internal/web/security.go`, `internal/web/i18n.go`, `internal/web/render.go`
- Create: `internal/web/assets/static/htmx.min.js` (htmx 2.0.4, da `https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js`; riportare lo SHA-256 nel messaggio di commit), `internal/web/assets/static/app.css`
- Create: `internal/web/assets/templates/layout.html`, `internal/web/assets/i18n/en.json`, `internal/web/assets/i18n/it.json`
- Test: `internal/web/session_test.go`, `internal/web/security_test.go`, `internal/web/i18n_test.go`

**Interfaces:**
- Consumes: `config.Config` (Task 1), `rpc.Credential` (Task 2).
- Produces:
  - `type Session struct { ID, CSRF string; Cred rpc.Credential; Lang string; Created, LastSeen time.Time }`.
  - `type SessionStore struct{ ... }`, `func NewSessionStore(idle, max time.Duration, now func() time.Time) *SessionStore`,
    `Create(cred rpc.Credential, lang string) *Session`, `Get(id string) (*Session, bool)`
    (aggiorna `LastSeen`, rifiuta le sessioni scadute), `Destroy(id string)`.
    Gli ID e i CSRF sono di 32 byte casuali, codificati in base64url.
  - Middleware in `security.go`:
    - `SecurityHeaders(next)`: gli header dei Global Constraints su ogni risposta;
    - `RequireSession(store, next)`: senza sessione valida reindirizza a `/login` con
      303, oppure, se la richiesta ha l'header `HX-Request`, risponde 200 con
      `HX-Redirect: /login`;
    - `CSRF(next)`: per POST, PUT e DELETE confronta il campo di form `csrf` o l'header
      `X-CSRF-Token` con `Session.CSRF`, e risponde 403 se non coincidono;
    - `type LoginLimiter`, con `Allow(ip string) bool` e `Fail(ip string)`: massimo
      `LoginMaxFailures` errori in `LoginWindow`.
  - `type Catalog`, `func LoadCatalogs(fs.FS) (Catalog, error)`,
    `func (c Catalog) T(lang, key string, args ...any) string`: una chiave mancante in
    `it` ricade su `en`; una chiave mancante ovunque restituisce `!key!`.
  - `func Negotiate(r *http.Request) string`: il cookie `swa_lang` vince, poi
    `Accept-Language`, infine `en`.
  - `type Renderer`, `func (r Renderer) Page(w, req, name string, data any)`: layout con
    `<meta name="htmx-config" content='{...}'>` (valori dei Global Constraints), lo
    script `/static/htmx.min.js`, e su `<body>` gli attributi
    `hx-headers='{"X-CSRF-Token":"<csrf>"}'` quando c'è una sessione. Selettore di lingua
    (link a `/lang?l=it|en`, che imposta il cookie `swa_lang`). Nessuno script né stile
    inline.

- [ ] **Step 1: Scrivere i test**
  - `TestSessionIdleExpiry`: con un orologio finto, se passano più di 30 min dall'ultimo `Get` la sessione non è più valida.
  - `TestSessionMaxExpiry`: dopo più di 8 h la sessione scade anche se usata di continuo.
  - `TestSecurityHeaders`: una risposta qualsiasi contiene esattamente la CSP e il `no-store` dei Global Constraints.
  - `TestRequireSessionRedirect`: senza cookie si ottiene 303 verso `/login`; con
    `HX-Request: true` si ottiene `HX-Redirect: /login`.
  - `TestBackAfterLogout` (Review Focus 4): si crea la sessione, la si distrugge, e un
    GET di una pagina protetta con il vecchio cookie dà 303 verso `/login`, con
    `Cache-Control: no-store`.
  - `TestCSRF`: un POST senza token dà 403, con il token di form passa, con l'header `X-CSRF-Token` passa.
  - `TestLoginLimiter`: dopo 5 errori `Allow` restituisce false; dopo 15 min torna true.
  - `TestCatalogsSameKeys`: `en.json` e `it.json` hanno lo stesso insieme di chiavi.
  - `TestNegotiate`: `Accept-Language: it-IT,it;q=0.9` dà `it`; il cookie `swa_lang=en` lo sovrascrive.
- [ ] **Step 2: Eseguire `go test ./internal/web/...`**: deve FALLIRE.
- [ ] **Step 3: Implementare** i file, con gli asset incorporati via `//go:embed assets`.
- [ ] **Step 4: Eseguire `go test -race ./internal/web/...`**: PASS.
- [ ] **Step 5: Commit** `feat(web): sessions, security middleware, i18n and layout`

### Task 7: Pagine di primo accesso, login, panoramica e avvisi

**Files:**
- Create: `internal/web/server.go`, `internal/web/handlers_setup.go`, `internal/web/handlers_auth.go`, `internal/web/handlers_dashboard.go`
- Create: `internal/audit/audit.go`
- Create i template: `setup.html`, `login.html`, `dashboard.html`, `unreachable.html`, `certmismatch.html`, `uncertain.html`
- Modify: `internal/web/assets/i18n/en.json`, `it.json`
- Test: `internal/web/handlers_test.go`

**Interfaces:**
- Consumes: Task 2-6 (`rpc.Client`, `softether.Prober`, `softether.ClassifyAdminIP`/`RestrictToLoopback`, `setup.Manager`, `SessionStore`, middleware, `Catalog`, `Renderer`).
- Produces:
  - `type Deps struct { Cfg config.Config; Client *rpc.Client; Prober softether.Prober; Setup *setup.Manager; Sessions *SessionStore; Audit *audit.Logger; Now func() time.Time }`.
  - `func NewServer(d Deps) http.Handler` con le rotte:
    - `GET /`: instradamento in base all'ultimo stato della sonda:
      - `StateEmptyPassword` porta a `/setup`;
      - `StateCertMismatch` porta a `/certmismatch`;
      - `StateUnreachable` porta a `/unreachable`;
      - altrimenti, senza sessione, `/login`; con sessione, `/dashboard`.
    - `GET|POST /setup`: campi `token`, `password`, `password2`. Chiama
      `setup.Manager.Complete`. In caso di successo crea la sessione e va a
      `/dashboard`. `ErrUncertain` porta alla pagina "esito incerto", che si aggiorna
      da sola via htmx (`hx-get="/status" hx-trigger="every 3s"`).
    - `GET|POST /login`: solo la password. In caso di successo `Test` con
      `Credential{"", pw}` crea la sessione; con `ErrUnauthorized` mostra un messaggio
      che cita sia la password errata sia la possibile restrizione IP (fatto 10).
      Applica il `LoginLimiter` per IP.
    - `POST /logout`.
    - `GET /dashboard`: `GetServerInfo` e `GetServerStatus`, più il banner di
      isolamento se `ClassifyAdminIP` non dà `Isolated`. Il banner elenca `Offending`
      (oppure "file assente") e contiene il pulsante "Limita a loopback".
    - `POST /adminip/restrict`: richiede il campo `confirm=yes`, chiama
      `RestrictToLoopback` e mostra il percorso del backup.
    - `GET /status`: frammento htmx con lo stato corrente della sonda.
    - `GET /unreachable`, `GET /certmismatch`: quest'ultima mostra l'impronta salvata,
      quella presentata e il comando
      `softether-webadmin trust-server-cert --fingerprint <presentata>`.
    - `GET /lang`, `GET /static/*`.
  - Qualunque chiamata JSON-RPC fatta con la credenziale della sessione che dà
    `ErrUnauthorized` distrugge la sessione e porta a `/login`.
  - `func (s *server) RunProbeLoop(ctx context.Context)`: esegue `Probe` ogni
    `ProbeInterval` e subito all'avvio, aggiorna lo stato condiviso (con un mutex) e
    chiama `Setup.Refresh`.
  - `audit.Logger`, con `Log(ctx, Event{Action, Role, Hub, RemoteIP, Method, Result string})`:
    scrive JSON su stderr con `slog`. Non accetta campi con valori sensibili.

- [ ] **Step 1: Scrivere i test** (httptest + `rpctest.FakeServer`, testo in `en`):
  - `TestFreshServerRedirectsToSetup`: con password vuota, `/` reindirizza a `/setup`.
  - `TestSetupWrongToken`: un POST con il token errato dà 200 con il messaggio
    `setup.bad_token`, e la password del server resta vuota.
  - `TestSetupFlow`: un POST con il token di `Setup` (letto da `ReadTokenFile`) e due
    password uguali di 12 o più caratteri dà 303 verso `/dashboard`, con il cookie di
    sessione impostato; il fake ha la password impostata.
  - `TestLoginWrongPassword`: 200 con `login.failed`; la sesta prova consecutiva dà
    429 con `login.rate_limited`.
  - `TestDashboardShowsServerInfo`: dopo il login la pagina contiene `Version` del fake.
  - `TestDashboardIsolationBanner`: con `adminip.txt` assente compare
    `adminip.missing`; con il file isolato il banner non c'è.
  - `TestRestrictAdminIPRequiresConfirm`: senza `confirm=yes` si ottiene 400; con la
    conferma il file diventa isolato.
  - `TestServerStopsWhileLoggedIn` (Review Focus 2): dopo il login si ferma il fake e
    si esegue la sonda, quindi `/` porta a `/unreachable` e la sessione resta valida;
    si riavvia il fake, si esegue la sonda, e `/dashboard` torna 200 con lo stesso cookie.
  - `TestUnauthorizedDestroysSession`: dopo il login la password del fake cambia,
    quindi `/dashboard` porta a `/login` e il vecchio cookie non è più valido.
  - `TestCertMismatchPage`: con il pin errato, `/` porta a `/certmismatch`, e la pagina
    contiene l'impronta presentata e il comando `trust-server-cert`.
  - `TestAuditNoSecrets`: si cattura l'output dell'audit durante setup e login; non
    deve contenere né la password né il token.
- [ ] **Step 2: Eseguire `go test ./internal/web/...`**: deve FALLIRE.
- [ ] **Step 3: Implementare** handler, template, voci dei cataloghi (en e it) e audit.
- [ ] **Step 4: Eseguire `go test -race ./...`**: PASS.
- [ ] **Step 5: Commit** `feat(web): first-access setup, login, dashboard and safety pages`

### Task 8: Sottocomandi e HTTPS del demone

**Files:**
- Create: `internal/tlsself/selfsigned.go`
- Modify: `cmd/softether-webadmin/main.go`
- Test: `internal/tlsself/selfsigned_test.go`, `cmd/softether-webadmin/main_test.go`

**Interfaces:**
- Consumes: tutti i Task precedenti.
- Produces:
  - `func EnsureSelfSigned(certPath, keyPath string, hosts []string, now time.Time) (created bool, err error)`:
    ECDSA P-256, validità 825 giorni, SAN = `hosts` (dall'host di `Listen`, più
    `localhost`, `127.0.0.1` e `::1`). Non sovrascrive file esistenti; la chiave ha
    permessi `0600`.
  - `serve`:
    1. carica la configurazione;
    2. usa `TLSCert`/`TLSKey` se impostati, altrimenti `EnsureSelfSigned` in
       `<StateDir>/tls/` e scrive nel log l'impronta SHA-256 del certificato;
    3. avvia `RunProbeLoop`;
    4. `http.Server` con `ReadHeaderTimeout` 10 s e `MinVersion` TLS 1.2;
    5. arresto ordinato su SIGTERM.

    Il client viene creato con `allowTOFU=true`, perché il primo collegamento a
    loopback è quello che fissa l'impronta (design 5.3).
  - `setup-token`: stampa `ReadTokenFile(RuntimeDir)`; senza token esce con 1 e il
    messaggio `no active setup token (server already configured or daemon not running)`.
  - `trust-server-cert [--fingerprint <hex>]`: si collega a `SoftEtherURL` senza
    inviare credenziali (solo handshake TLS) e legge l'impronta presentata. Se è passato
    `--fingerprint`, deve coincidere, altrimenti esce con 1. Salva l'impronta nel
    PinStore e la stampa.

- [ ] **Step 1: Scrivere i test**
  - `TestEnsureSelfSignedCreatesOnce`: la prima chiamata dà `created==true`, la seconda false; il SAN contiene `127.0.0.1`; la chiave ha permessi `0600`.
  - `TestSetupTokenCommand`: con un file di token in una `RuntimeDir` temporanea viene stampato il token e si esce con 0; senza file si esce con 1.
  - `TestTrustServerCert`: contro un `httptest.NewTLSServer`, il pin salvato è uguale
    a `Fingerprint(server.Certificate().Raw)`; con un `--fingerprint` errato si esce
    con 1 e il pin non viene scritto.
- [ ] **Step 2: Eseguire `go test ./cmd/... ./internal/tlsself/...`**: deve FALLIRE.
- [ ] **Step 3: Implementare.** Per rendere testabile `main.go`, spostare la logica in una funzione `run(args []string, stdout, stderr io.Writer) int`.
- [ ] **Step 4: Eseguire `go test -race ./...`**: PASS.
- [ ] **Step 5: Commit** `feat: serve, setup-token and trust-server-cert commands`

### Task 9: Test di integrazione con vpnserver reale e CI

**Files:**
- Create: `test/integration/vpnserver_test.go` (build tag `integration`)
- Create: `test/integration/harness.go`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: il binario o i package dei Task 1-8.
- Produces:
  - Harness:
    - `StartVPNServer(t) (apiURL string, stop func())`: esegue con `docker`, oppure
      `podman` se `CONTAINER_ENGINE=podman`, il comando
      `run -d --rm -p 127.0.0.1::5555 docker.io/softethervpn/vpnserver:5.2.5189`;
    - ricava la porta con `port <id> 5555`;
    - attende fino a 60 s che una `Test` dia `StateEmptyPassword`.
  - `ci.yml`, su push e pull_request, con tre job su `ubuntu-24.04`, tutti con `actions/setup-go` e `go-version-file: go.mod`:
    - `test`: `go vet ./...` e `go test -race ./...`;
    - `integration`: `go test -tags integration ./test/integration/... -v`;
    - `package`: Task 10.

- [ ] **Step 1: Scrivere i test**
  - `TestRealFirstAccess`: si avvia il container e si costruisce
    `web.NewServer` sull'API reale (con `allowTOFU`). Poi:
    1. `/` porta a `/setup`;
    2. il token si legge dal file;
    3. un POST a `/setup` porta a `/dashboard`;
    4. la pagina contiene `5.02`;
    5. la sonda dà `StatePasswordSet`.
  - `TestRealLoginAndLogout`: si fa il login con la password impostata, poi `/logout`,
    e `/dashboard` porta a `/login`.
  - `TestRealPinMismatch`: si sovrascrive il pin con un'impronta finta, quindi `/` porta
    a `/certmismatch`; si esegue `trust-server-cert`, e `/` torna a `/login`.
- [ ] **Step 2: Eseguire `go test -tags integration ./test/integration/... -v`** in locale, con podman o docker: PASS.
- [ ] **Step 3: Scrivere `ci.yml`** con i job `test` e `integration`, e fare il push su un branch.
- [ ] **Step 4: Verificare con `gh run watch`** che i job `test` e `integration` siano verdi.
- [ ] **Step 5: Commit** `test: integration tests against softethervpn/vpnserver:5.2.5189 and CI`

### Task 10: Pacchetti deb/rpm e unit systemd

**Files:**
- Create: `packaging/nfpm.yaml`, `packaging/softether-webadmin.service`, `packaging/config.toml`, `packaging/postinstall.sh`, `packaging/preremove.sh`, `packaging/postremove.sh`
- Modify: `.github/workflows/ci.yml` (job `package`)

**Interfaces:**
- Consumes: il binario (`version` con `-ldflags "-X main.version=<ver>"`).
- Produces:
  - **Pacchetto** `softether-webadmin`, architetture `amd64`/`arm64` (deb) e
    `x86_64`/`aarch64` (rpm). Contenuto:
    - `/usr/bin/softether-webadmin`;
    - `/usr/lib/systemd/system/softether-webadmin.service`;
    - `/etc/softether-webadmin/config.toml` come file di configurazione (`config|noreplace`).

    Dipendenze: raccomanda `softether-vpnserver`, senza dipendenze obbligatorie.
  - **Unit:**
    - `ExecStart=/usr/bin/softether-webadmin serve --config /etc/softether-webadmin/config.toml`;
    - `User=root`, `RuntimeDirectory=softether-webadmin`, `RuntimeDirectoryMode=0700`,
      `StateDirectory=softether-webadmin`, `StateDirectoryMode=0700`;
    - `NoNewPrivileges=yes`, `ProtectSystem=strict`,
      `ReadWritePaths=-/var/lib/softether`, `ProtectHome=yes`, `PrivateTmp=yes`,
      `PrivateDevices=yes`;
    - `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`,
      `ProtectControlGroups=yes`;
    - `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `LockPersonality=yes`,
      `MemoryDenyWriteExecute=yes`, `RestrictRealtime=yes`,
      `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`;
    - `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `Restart=on-failure`;
    - `After=network-online.target softether-vpnserver.service`,
      `Wants=network-online.target`, `WantedBy=multi-user.target`.
  - **`postinstall.sh`:**
    - `systemctl daemon-reload`, solo se esiste `/run/systemd/system`;
    - se `/var/lib/softether` esiste e `adminip.txt` no, lo crea (`0600`) con
      `127.0.0.1/32` e `::1/128` e un commento, e stampa una nota;
    - se il file esiste già non lo tocca e stampa
      `NOTE: existing adminip.txt kept unchanged; the web UI will warn if it is not loopback-only`;
    - non abilita né avvia il servizio, e stampa
      `systemctl enable --now softether-webadmin`.
  - **`preremove.sh`:** alla rimozione (non all'upgrade) esegue `systemctl disable --now`.
  - **`postremove.sh`:** `daemon-reload`.
  - **Job CI `package`:**
    - compila per `linux/amd64` e `linux/arm64` (`CGO_ENABLED=0`), con nfpm a una
      release fissata;
    - verifica l'installazione in `debian:trixie` e `rockylinux/rockylinux:8`, `:9` e
      `:10` (amd64): il pacchetto si installa, `softether-webadmin version` funziona e
      la unit è presente;
    - carica i pacchetti come artifact.

- [ ] **Step 1: Scrivere lo script di prova** `packaging/test-install.sh <pkg>`. Installa il
  pacchetto con apt o dnf, verifica `softether-webadmin version`,
  `test -f /usr/lib/systemd/system/softether-webadmin.service` e
  `systemd-analyze verify` della unit. Con `/var/lib/softether` creato prima
  dell'installazione, verifica che `adminip.txt` venga creato con `0600`. Con un
  `adminip.txt` preesistente, verifica che resti identico.
- [ ] **Step 2: Eseguirlo in locale** in `debian:trixie` e `rockylinux/rockylinux:9`
  con podman: deve FALLIRE, perché il pacchetto non esiste ancora.
- [ ] **Step 3: Scrivere** `nfpm.yaml`, la unit, la configurazione e gli script, poi costruire i pacchetti.
- [ ] **Step 4: Rieseguire lo script** sulle 4 distribuzioni in locale: PASS. Aggiungere il job
  `package` alla CI e verificarlo verde con `gh run watch`.
- [ ] **Step 5: Commit** `build: deb/rpm packages with hardened systemd unit`
