# softether-webadmin — documento di design

Data: 2026-11-05 · Stato: bozza da approvare (rev. 2: integrata la revisione esterna)

## 1. Intento e perché

Interfaccia web di amministrazione per **SoftEther VPN Server 5.x**, eseguita come
demone separato scritto in **Go**, uno per ciascun server VPN.

Perché:

- **Niente client da installare e mantenere.** Oggi l'amministrazione passa dal
  Server Manager per Windows, da installare e aggiornare su ogni postazione,
  oppure da `vpncmd`.
- **Un server nuovo nasce senza configurazione.** Con i pacchetti deb/rpm
  (`softether-vpnserver`, vedi PR upstream #2327) il primo passo (certificato,
  porte, protocolli, cluster) oggi si fa per forza da `vpncmd` o dal Server Manager
  per Windows. L'interfaccia web deve permettere di mettere in piedi il server.
- **Più sicurezza.** L'amministrazione di SoftEther viene chiusa su localhost con
  `adminip.txt`. La garanzia è basata sull'IP: da localhost potrebbe tentare l'accesso
  anche un altro processo locale, ma nessun host remoto può più farlo (sezione 5.1). L'interfaccia web non va mai esposta su internet, ma
  solo sulla rete di gestione.
- **Contributo upstream.** Quando sarà pronta verrà proposta al progetto
  SoftEtherVPN/SoftEtherVPN.

## 2. Obiettivi, non-obiettivi, anti-obiettivi

**Obiettivi**

- Coprire le funzioni del Server Manager per Windows, in due versioni (sezione 6).
- Due ruoli: **amministratore del server** e **amministratore di Hub**. Il secondo
  vede e gestisce solo il proprio Hub.
- Interfaccia in **italiano e inglese** fin dall'inizio, con testi separati dal codice.
- Pacchetti deb/rpm con unit systemd, sulle stesse distribuzioni dei pacchetti
  SoftEther: Debian 13 ed EL 8/9/10, x86_64 e aarch64.

**Non-obiettivi**

- Una console centrale che gestisce più server: ogni server ha la sua interfaccia.
- Un archivio utenti proprio. Si usano le credenziali di SoftEther: password del
  server, oppure nome e password di un Hub.
- Modifiche al codice C di SoftEther. Sono ammesse solo come contributi separati, se
  si rendono necessarie.
- Gestire VPN Client o VPN Bridge in sé (vpnclient/vpnbridge).

**Anti-obiettivi** (fallimento anche se "funziona")

- Esporre l'amministrazione di SoftEther o l'interfaccia web su internet per impostazione predefinita.
- Salvare in chiaro su disco password di SoftEther.
- Richiedere Node/npm o una toolchain frontend per la build.

## 3. Fatti tecnici verificati

Verificati il 2026-11-05 sul sorgente upstream (master, 5.2.5189) e con test reali
su vpnserver in container.

1. **L'amministrazione non si può legare a localhost.** Protocollo del Server
   Manager, JSON-RPC e `/admin` viaggiano sulle stesse porte dei listener VPN
   (443/992/1194/5555), e i listener ascoltano su tutte le interfacce senza un
   indirizzo di bind configurabile.
2. **`adminip.txt` limita da dove si può amministrare** (`CheckAdminSourceAddress()`
   in `src/Cedar/Admin.c`, chiamata sia dal protocollo nativo sia dalla JSON-RPC).
   - Si trova nella directory dei dati (`SE_DBDIR`: `/var/lib/softether` con i
     pacchetti FHS, altrimenti la directory del binario).
   - Viene riletto a ogni accesso.
   - Se il file non esiste, l'amministrazione è consentita da qualunque IP. Se
     esiste, solo dagli indirizzi elencati.
   - Una riga per voce: `<ip/maschera> [nome_hub]`. Senza nome Hub vale per tutti.
     Sono supportati commenti `#` e `//`.
3. **La JSON-RPC (`POST https://<host>:<porta>/api/`) usa lo stesso `AdminDispatch`
   del Server Manager.** Espone 148 metodi, che coprono tutte le 130 chiamate del
   Server Manager e le 132 di vpncmd.
   - Una batteria di 47 scritture reali (Hub, utenti, criteri, elenchi degli accessi,
     SecureNAT, certificati, IPsec, OpenVPN, cascate, switch L3, ecc.) è riuscita
     in 46 casi.
   - Il bridge locale è fallito solo perché il container non lo supporta (errore 84).
4. **Autenticazione:** HTTP Basic.
   - Nome utente vuoto o `administrator` significa amministratore del server.
   - Nome utente uguale al nome di un Hub significa amministratore di quell'Hub, con
     la password dell'Hub.
   - I permessi sono imposti dal server: un amministratore di Hub che chiama
     `CreateListener` riceve l'errore 52, `Not enough privileges`.
5. **I `Set*` sostituiscono l'intera struttura.** Un `SetHub` con il solo
   `MaxSession` ha messo l'Hub offline e azzerato `NoEnum`. Ogni modifica deve fare
   lettura, modifica e riscrittura dell'oggetto completo.
6. **Documentazione incompleta.**
   - Il README ufficiale (`developer_tools/vpnserver-jsonrpc-clients/README.md`)
     documenta 133 metodi su 148.
   - Mancano: `AddWgk`, `DeleteWgk`, `EnumWgk`, `GetProtoOptions`, `SetProtoOptions`,
     `GetPortsUDP`, `SetPortsUDP`, `GetServerCipherList`, `EnumEthVLan`,
     `SetEnableEthVLan`, `AddLicenseKey`, `DelLicenseKey`, `EnumLicenseKey`,
     `GetLicenseStatus`, `Debug`. I formati dei parametri vanno ricavati da
     `src/Cedar/Admin.c` (funzioni `In*`/`Out*`).
7. **Tipi JSON:** il suffisso indica il tipo (`_str`, `_utf`, `_u32`, `_u64`,
   `_bool`, `_ip`, `_bin` base64, `_dt`). Gli elenchi sono array di oggetti.
   I certificati vanno in PEM codificato base64 dentro `_bin`.
8. **Effetti particolari.** `SetConfig` riavvia il server. La JSON-RPC si può
   disattivare con `DisableJsonRpcWebApi` nella configurazione (va lasciata attiva).
9. **Server appena installato:** nessuna password di amministrazione impostata. Finché
   la password è vuota, `JsonRpcAuthLogin()` tratta **qualunque** nome utente e password
   come amministratore del server (`Admin.c`, controllo `empty_pw_hash`), sempre nei
   limiti di `adminip.txt`.

10. **Errori di autenticazione indistinguibili.** Una password errata e un indirizzo
    rifiutato da `adminip.txt` producono entrambi HTTP 401
    (`AdminWebSendUnauthorized()`).

## 4. Decisioni prese

**Decise da Francesco**

- Demone separato in **Go**, uno per server, raggiungibile solo dalla rete di gestione.
- Amministrazione di SoftEther raggiungibile solo da localhost, dove gira il demone.
- Frontend con **htmx**.
- Due ruoli: amministratore del server e amministratore di Hub.
- **Prima versione:** configurazione del server. **Seconda versione:** gestione
  quotidiana degli Hub (sezione 6).
- Lingue: almeno italiano e inglese.
- Repository: `~/lavoro/softether-webadmin`, issue tracker beads (`bd`).
- Proposta al progetto upstream quando sarà pronta.

**Scelte mie** (da confermare leggendo)

- **Stack:**
  - Go con `net/http` della libreria standard (routing della versione 1.22 o
    successive), htmx e template lato server;
  - template con `html/template` della libreria standard: niente strumenti di
    generazione aggiuntivi nella build, più semplice da rivedere per upstream;
  - un solo binario con template, CSS e JS incorporati (`embed.FS`), CSS leggero
    senza build.
- **Nessun segreto salvato:**
  - l'utente accede con credenziali SoftEther, che il demone verifica chiamando la
    JSON-RPC;
  - le credenziali restano solo nella sessione in memoria, e un riavvio del demone
    richiede un nuovo accesso.
- **Primo accesso con token monouso:** se il server non ha password di amministrazione
  (fatto 9), raggiungere l'interfaccia non basta per prenderne il controllo.
  - Al primo avvio il demone genera un **token di configurazione monouso** e lo scrive
    nel journal; lo stampa anche il comando `softether-webadmin setup-token`.
  - La pagina di primo accesso chiede il token e poi obbliga a impostare la password
    del server, prima di mostrare qualunque altra pagina.
  - Il token scade quando la password risulta impostata.
- **Rete:**
  - il demone ascolta su `127.0.0.1` per impostazione predefinita, e l'indirizzo è
    configurabile (per esempio l'IP della rete di gestione);
  - serve HTTPS con un certificato configurabile; se manca, ne genera uno
    autofirmato al primo avvio;
  - verso SoftEther si collega a `https://127.0.0.1:5555/api/` (configurabile).
- **Protezioni web:**
  - cookie di sessione `HttpOnly`, `Secure` e `SameSite=Strict`;
  - token CSRF su ogni richiesta che modifica qualcosa, anche quelle htmx;
  - CSP senza script inline;
  - limite ai tentativi di accesso e scadenza della sessione per inattività.
- **Log delle operazioni** su journald: ruolo, Hub, IP del browser, metodo
  JSON-RPC ed esito. Mai password né parametri sensibili.
- **Installazioni supportate:**
  - riferimento principale: i pacchetti FHS di SoftEther (`SE_DBDIR=/var/lib/softether`,
    unit `softether-vpnserver.service`), costruiti dal workflow `packages` del fork
    `fdefilippo/SoftEtherVPN` finché la PR #2327 non è accettata upstream;
  - matrice di build: Debian 13 ed EL 8/9/10, x86_64 e aarch64, la stessa del workflow;
  - per gli altri layout (tarball, `/usr/local`, percorsi personalizzati come il cluster
    su `/srv/softether`) restano configurabili sia il percorso di `adminip.txt` sia
    l'indirizzo della JSON-RPC, e la dipendenza da `softether-vpnserver` è solo
    raccomandata, non obbligatoria.
- **Pacchetto `softether-webadmin`** (deb/rpm):
  - binario, unit systemd e file di configurazione in `/etc/softether-webadmin/`;
  - se `adminip.txt` non esiste, lo crea con `127.0.0.1/32` e `::1/128` e lo
    segnala chiaramente nell'output di installazione;
  - un `adminip.txt` già esistente non viene mai modificato automaticamente; il suo
    contenuto viene però verificato (sezione 5.1).
- **i18n:**
  - cataloghi di messaggi per lingua, separati dal codice;
  - lingua dal browser (`Accept-Language`) con selettore manuale;
  - per l'italiano, la terminologia di `strtable_it.stb` (Hub virtuale, connessione
    a cascata, scheda di rete virtuale, ecc.).
- **Licenza:** Apache-2.0, come SoftEther.
- **Client Go della JSON-RPC:** tipizzato e generato, non scritto a mano metodo per
  metodo.
  - Il generatore vive in questo repository ed è scritto in Go. Legge gli esempi
    JSON del README ufficiale (133 metodi) e un file di definizioni correttive e
    aggiuntive per i 15 metodi non documentati, ricavate da `Admin.c`.
  - Il README di input è fissato a un commit upstream preciso, registrato nel
    repository. Gli esempi non garantiscono completezza dei campi, valori ammessi o la
    distinzione fra campo assente e valore zero: le definizioni correttive coprono
    questi casi e i test di conservazione (sezione 5.5) li verificano.
  - Il codice generato viene committato, quindi la build non richiede .NET.
  - Estendere `developer_tools/vpnserver-jsonrpc-codegen` (C#, .NET 2.1 ormai fuori
    supporto) e documentare i 15 metodi sono contributi upstream **successivi e
    separati**: non bloccano questo lavoro.
- **Hub nella prima versione:** elenco e creazione minimi, perché cascate, bridge
  locale e switch L3 richiedono un Hub esistente.

## 5. Architettura

```
 browser (rete di gestione)
     │ HTTPS, cookie di sessione + CSRF
     ▼
 softether-webadmin (Go, un processo per server)
     │ HTTPS + HTTP Basic (credenziali della sessione)
     ▼
 vpnserver  /api/  su 127.0.0.1:5555   ← adminip.txt: solo 127.0.0.1 e ::1
```

- Ogni operazione dell'interfaccia corrisponde a uno o più metodi JSON-RPC.
- Le modifiche usano sempre lettura, modifica e riscrittura (fatto 5).
- Se due amministratori modificano lo stesso oggetto, vince l'ultimo che salva. Va
  bene così per la prima versione, ma l'interfaccia deve sempre ricaricare l'oggetto
  aggiornato dopo un salvataggio.
- Gli errori SoftEther (codice e messaggio) vanno mostrati all'utente, tradotti
  quando possibile.

## 5bis. Comportamenti definiti (sicurezza e affidabilità)

### 5.1 Isolamento dell'amministrazione
- `adminip.txt` autorizza **indirizzi IP**, non processi. Con `127.0.0.1/32` e
  `::1/128` nessun host remoto può amministrare, ma un processo locale sì. Va scritto
  così nella documentazione, senza promettere "solo il demone".
- **Controllo all'avvio e a ogni accesso.** Il demone legge `adminip.txt` (percorso
  configurabile) e classifica lo stato:
  - **isolato:** il file contiene solo voci di loopback;
  - **non isolato:** il file manca, oppure contiene voci non di loopback.
- **Stato non isolato.** Il demone funziona, ma:
  - mostra un avviso permanente in tutte le pagine all'amministratore del server, con
    le voci problematiche;
  - scrive l'avviso nel journal a ogni avvio;
  - non modifica mai il file automaticamente. Per limitarlo a loopback c'è un'azione
    esplicita con conferma, che fa prima una copia di backup.

### 5.2 Primo accesso (password vuota) e token
- **Rilevamento dello stato** con una sonda: chiamata `Test` con nome utente vuoto e
  una password casuale di 32 byte.
  - **Successo:** il server ha la password vuota (fatto 9).
  - **401:** password impostata, oppure IP non autorizzato (fatto 10). L'interfaccia
    mostra il login normale; se il login fallisce, il messaggio cita entrambe le
    possibilità.
  - **Errore di connessione o TLS:** server irraggiungibile. Mostra una pagina di
    errore e non apre il flusso del token.
- **Token.** Quando la sonda rileva la password vuota, il demone genera un token
  casuale e lo salva in `/run/softether-webadmin/setup-token`, con permessi `0600` e
  proprietario l'utente del servizio.
  - `softether-webadmin setup-token`, da eseguire come root o come utente del
    servizio, legge quel file: non serve un canale di comunicazione con il processo.
  - Il token si scrive anche nel journal.
- **Consumo atomico.** La configurazione iniziale è serializzata da un lock nel demone:
  1. verifica il token;
  2. rifà la sonda (la password deve essere ancora vuota);
  3. chiama `SetServerPassword`;
  4. rifà la sonda (deve rispondere 401);
  5. cancella il token.

  Una seconda richiesta concorrente trova il token consumato e riceve "server già
  configurato".
- **Cambiamenti esterni.** La sonda si ripete a ogni tentativo di accesso e ogni
  60 secondi.
  - Se la password viene impostata dall'esterno, il token viene invalidato.
  - Se viene rimossa dall'esterno, si genera un nuovo token e si segnala nel journal.
  - Le sessioni aperte la cui password non è più valida vengono chiuse alla prima
    chiamata che risponde 401.

### 5.3 Fiducia TLS verso vpnserver
- **Rischio.** Il demone invia credenziali di amministrazione su loopback. Se vpnserver
  è fermo, un processo locale non privilegiato potrebbe mettersi in ascolto sulla
  stessa porta (per esempio 5555) e raccoglierle.
- **Impronta fissata.**
  - Al primo collegamento riuscito (fiducia al primo uso, oppure con l'impronta
    passata con `softether-webadmin trust-server-cert`) il demone salva l'impronta
    SHA-256 del certificato di vpnserver in
    `/var/lib/softether-webadmin/server-cert.sha256`.
  - In seguito non invia credenziali a un server con un'impronta diversa.
- **Rotazione dall'interfaccia.** Quando il certificato viene cambiato con
  `SetServerCert`, il demone calcola l'impronta del nuovo certificato prima della
  chiamata, aggiorna l'impronta salvata dopo la conferma, e verifica con una nuova
  connessione.
- **Rotazione esterna** (vpncmd, Server Manager, `SetConfig`). Le chiamate vengono
  bloccate e appare una pagina "certificato del server cambiato" con vecchia e nuova
  impronta. Per riallineare serve `softether-webadmin trust-server-cert` sull'host:
  è un'azione locale e privilegiata, mai dal browser.

### 5.4 Operazioni che possono interrompere il collegamento
- **Impedite**, con messaggio:
  - disattivare o eliminare il listener usato dal demone;
  - ripristinare una configurazione (`SetConfig`) che imposta
    `DisableJsonRpcWebApi true` o che non contiene il listener usato dal demone (il
    file viene analizzato prima dell'invio);
  - modificare `adminip.txt` in modo da escludere il loopback.
- **Con conferma esplicita** che spiega l'effetto: `SetConfig` (riavvio del server),
  `SetFarmSetting` (cambio di modalità del cluster), `SetServerCert`,
  `SetServerPassword`, `DeleteHub`. Dopo `SetServerPassword` riuscito, il demone
  aggiorna la credenziale della sessione corrente.
- **Esito incerto.** Se la connessione cade durante una scrittura, l'interfaccia mostra
  "esito incerto, verifica in corso". Il demone ripete la sonda finché il server non
  risponde, con un timeout, poi rilegge l'oggetto e mostra lo stato reale.
- **Mai ripetere automaticamente una scrittura**: una risposta persa non dimostra che
  l'operazione sia fallita.

### 5.5 Lettura, modifica e riscrittura
- Il demone **serializza le scritture sullo stesso oggetto** (lock per metodo e
  chiave, per esempio Hub o Hub più utente). Sotto il lock:
  1. rilegge l'oggetto aggiornato con `Get*`;
  2. applica **solo i campi modificati** nel form (il form invia i valori originali
     insieme ai nuovi, e il demone confronta);
  3. chiama `Set*` e rilegge l'oggetto.
- Se un campo modificato nel form risulta cambiato sul server rispetto al valore
  originale del form, la scrittura viene rifiutata con "l'oggetto è stato modificato
  da qualcun altro" e il form viene ricaricato.
- Le modifiche concorrenti fatte fuori dal demone (vpncmd, Server Manager) restano un
  **limite esplicito**: il controllo copre solo i campi toccati.
- **Nessuna simmetria Get/Set data per scontata.** Per ogni metodo `Set*` usato c'è un
  test di conservazione: `Get`, poi `Set` con i dati invariati, poi `Get` di nuovo, e
  i due risultati devono essere identici. Su un vpnserver reale, nella CI.

### 5.6 Cache e htmx
- `Cache-Control: no-store` su tutte le pagine autenticate, sui frammenti htmx e sui
  download (configurazione, log, certificati).
- Configurazione di htmx compatibile con la CSP e senza cache locale:
  - `htmx.config.allowEval = false` e `allowScriptTags = false`;
  - `historyCacheSize = 0` e `refreshOnHistoryMiss = true`;
  - `includeIndicatorStyles = false`, perché gli stili inline violerebbero la CSP;
  - `selfRequestsOnly = true`.

## 6. Perimetro

**Prima versione: mettere in piedi un server** (solo amministratore del server)

Senza utenti e autenticazione degli Hub la prima versione **prepara** il server, ma per
renderlo utilizzabile dagli utenti VPN serve ancora un altro strumento (vpncmd o il
Server Manager) fino alla seconda versione. Il perimetro resta quello sotto, diviso in
tappe verificabili, ciascuna rilasciabile:

1. fondamenta e primo accesso;
2. listener, certificato e cifratura;
3. protocolli;
4. Hub minimi, cascate, bridge locale e switch L3;
5. cluster, DDNS/VPN Azure, syslog e log;
6. configurazione (backup e ripristino).

- Primo accesso: impostazione della password di amministrazione.
- Panoramica: informazioni e stato del server, capacità (`GetCaps`).
- Listener: elenco, aggiunta, rimozione, attivazione e disattivazione.
- Certificato SSL del server: caricamento PEM (certificato e chiave), generazione
  di un certificato autofirmato, download; cifratura (`Get/SetServerCipher`,
  `GetServerCipherList`).
- Protocolli: IPsec/L2TP/EtherIP (con ID EtherIP), OpenVPN/SSTP, opzioni dei
  protocolli (`Get/SetProtoOptions`), WireGuard (chiavi), porte UDP.
- Hub virtuali: elenco e creazione minima.
- Connessioni a cascata, bridge locale (schede disponibili, TAP), switch L3
  (switch, interfacce, tabelle di routing).
- Cluster (`Get/SetFarmSetting`, stato e membri).
- DDNS e VPN Azure; keep-alive; syslog.
- File di log: elenco e download (`EnumLogFile`, `ReadLogFile`).
- Configurazione: download di `vpn_server.config` (`GetConfig`) e ripristino
  (`SetConfig`, con conferma esplicita perché riavvia il server).

**Seconda versione: gestione quotidiana** (amministratore del server e
amministratore di Hub)

- Accesso come amministratore di Hub, con vista limitata al proprio Hub.
- Hub: proprietà complete, online/offline (solo amministratore del server), opzioni
  amministrative ed estese, messaggio dell'Hub.
- Utenti, con tutti i tipi di autenticazione (anonima, password, certificato
  utente, certificato firmato, RADIUS, dominio NT), e gruppi; criteri di sicurezza.
- Elenchi degli accessi (IPv4/IPv6), restrizioni per IP di origine.
- SecureNAT: NAT virtuale e server DHCP virtuale, tabelle NAT e DHCP.
- Sessioni attive con dettagli e disconnessione, tabelle MAC e IP.
- Statistiche e stato dell'Hub.
- CA attendibili, elenco di revoche (CRL), RADIUS, log dell'Hub.

## 7. Qualità e test

- Test di integrazione contro un **vpnserver reale in container** (podman/docker),
  come nei test del 2026-11-05: ogni pagina viene verificata rileggendo l'oggetto
  via API dopo il salvataggio.
- Test HTTP delle pagine e dei frammenti htmx: risposte, permessi per ruolo, CSRF,
  sessione.
- Build e pacchetti nella CI GitHub, sulle stesse distribuzioni dei pacchetti
  SoftEther.

## 8. Lasciato al costruttore

- Versione di Go, struttura dei package, CSS.
- Formato del file di configurazione e dei cataloghi delle traduzioni.
- Libreria o approccio per il pacchetto deb/rpm (per esempio `nfpm`).
- Ordine di implementazione delle pagine della prima versione.
