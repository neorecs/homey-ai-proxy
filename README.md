# Homey AI Proxy

Een kleine, veilige API-tussenlaag tussen ChatGPT/Codex en Homey Pro. De proxy draait lokaal, bijvoorbeeld op Synology Docker of Portainer, en voorkomt dat een AI-client onbeperkt Homey-acties kan uitvoeren.

## Architectuur

```text
ChatGPT/Codex
  -> HTTPS/API endpoint op Synology Docker
  -> Homey AI Proxy
  -> Homey Pro API / bestaande Homey-flows
  -> Homey-apparaten
```

## Ontwerpprincipe: local-first

Alle normale Homey-acties moeten tussen de Docker-container en Homey Pro lokaal verlopen. De proxy gebruikt dus standaard een lokaal Homey-adres, bijvoorbeeld `http://10.5.2.201`, en laat ChatGPT/Codex nooit direct met Homey praten.

Cloud-authenticatie mag later alleen worden gebruikt om OAuth2-tokens of een Homey-sessie te verkrijgen. Runtime-acties zoals devices ophalen, flows lezen en allowlisted flows starten moeten daarna via de lokale Homey Pro API lopen. Als lokaal verbinden niet lukt, moet de proxy falen in plaats van stilletjes over te schakelen naar cloud-control. Dit voorkomt extra cloudverkeer en helpt request limits vermijden.

De MVP gebruikt veilige defaults:

- alleen flows uit `config.yaml` of flows die beginnen met `AI -` mogen worden gestart;
- risicovolle opdrachten met `blocked_keywords` worden geblokkeerd;
- devices en flows worden gecachet;
- verzoeken naar Homey gaan via een queue met rate limiting;
- secrets staan alleen in `.env`, nooit in Git.

## Repository-opbouw

```text
homey-ai-proxy/
  docker-compose.yml
  Dockerfile
  .env.example
  config.yaml.example
  README.md
  app/
    main.py
    homey_client.py
    config.py
    rate_limiter.py
    cache.py
    logger.py
    intent_router.py
    security.py
  logs/
  tests/
```

## Lokaal starten

Maak eerst lokale configuratiebestanden:

```bash
cp .env.example .env
cp config.yaml.example config.yaml
```

Laat voor de eerste test `HOMEY_USE_MOCK=true` staan. Start daarna:

```bash
docker compose up --build
```

Controleer de healthcheck:

```bash
curl http://localhost:8000/health
```

Zonder PowerShell kun je de browserhulp openen:

```text
http://localhost:8000/setup
```

Op Synology is dat bijvoorbeeld `http://10.5.1.150:18080/setup`.

## Synology / Portainer

1. Plaats de repository op je NAS, bijvoorbeeld in een Docker-map.
2. Kopieer `.env.example` naar `.env` en vul je eigen waarden in.
3. Kopieer `config.yaml.example` naar `config.yaml` en pas de allowlist aan.
4. Maak een Portainer Stack aan met de inhoud van `docker-compose.yml`.
5. Deploy de stack.
6. Controleer `http://<nas-ip>:8000/health`.

De compose-file mount `./logs:/app/logs`, zodat logs buiten de container bewaard blijven.

## Secrets veilig gebruiken

Zet echte tokens alleen in `.env`:

```env
PROXY_API_KEY=kies-een-lange-random-api-key
HOMEY_TOKEN=je-echte-homey-token
OPENAI_API_KEY=alleen-als-openai-enabled-true-is
```

Commit nooit `.env` of `config.yaml` met privégegevens. Deze bestanden staan bewust in `.gitignore`. Gebruik alleen `.env.example` en `config.yaml.example` als voorbeelden.

`PROXY_API_KEY` is optioneel voor lokaal ontwikkelen, maar aanbevolen zodra je echte Homey-acties toestaat. Als deze waarde is gezet, moet elke Homey API-call de header `X-API-Key` meesturen. `/health` blijft zonder key beschikbaar voor Docker-healthchecks.

## Allowlist aanpassen

Voeg nieuwe veilige flows toe aan `config.yaml`:

```yaml
allowed_flows:
  - "AI - Presence test"
  - "AI - Nieuwe veilige flow"

command_map:
  "nieuwe test": "AI - Nieuwe veilige flow"
```

Flows die beginnen met `AI -` zijn toegestaan, behalve wanneer ze geblokkeerde woorden bevatten. Houd risicovolle acties buiten de allowlist, zoals sloten openen, alarm uitschakelen, garagedeuren openen, 3D-printers starten of elektrische kachels inschakelen.

## API voorbeelden

Health:

```bash
curl http://localhost:8000/health
```

Homey status:

```bash
curl -H "X-API-Key: jouw-proxy-api-key" http://localhost:8000/homey/status
```

Homey readiness zonder flows te starten:

```bash
curl -H "X-API-Key: jouw-proxy-api-key" http://localhost:8000/homey/readiness
curl -H "X-API-Key: jouw-proxy-api-key" "http://localhost:8000/homey/readiness?live=true"
```

Devices met cache:

```bash
curl -H "X-API-Key: jouw-proxy-api-key" "http://localhost:8000/homey/devices?zone=Woonkamer&type=light"
curl -H "X-API-Key: jouw-proxy-api-key" "http://localhost:8000/homey/devices?refresh=true"
```

Flows:

```bash
curl -H "X-API-Key: jouw-proxy-api-key" http://localhost:8000/homey/flows
```

Flow starten:

```bash
curl -X POST http://localhost:8000/homey/flows/start \
  -H "X-API-Key: jouw-proxy-api-key" \
  -H "Content-Type: application/json" \
  -d "{\"flow_name\":\"AI - Presence test\"}"
```

Natuurlijke opdracht:

```bash
curl -X POST http://localhost:8000/homey/command \
  -H "X-API-Key: jouw-proxy-api-key" \
  -H "Content-Type: application/json" \
  -d "{\"command\":\"test presence\"}"
```

Deze opdracht wordt rule-based vertaald naar `AI - Presence test`.

## OpenAI function calling

De code is voorbereid met de feature flag:

```env
OPENAI_ENABLED=false
```

In deze MVP wordt OpenAI nog niet aangeroepen. De veilige basis is eerst rule-based: een opdracht wordt alleen uitgevoerd als die in `command_map` staat en daarna door de allowlist komt. Later kan OpenAI tool/function calling worden toegevoegd, waarbij het model uitsluitend mag kiezen uit vooraf gedefinieerde intents.

## Echte Homey-client

De MVP draait standaard met de mock-client:

```env
HOMEY_USE_MOCK=true
```

Voor echte Homey-aansturing:

```env
HOMEY_USE_MOCK=false
HOMEY_BASE_URL=http://10.5.2.201
HOMEY_TOKEN=je-homey-token
HOMEY_TRANSPORT=local
HOMEY_AUTH_MODE=static_token
```

De HTTP-client ondersteunt status, devices, flows en het starten van bestaande flows. Runtime-verkeer hoort lokaal naar Homey Pro te gaan. Afhankelijk van je Homey Pro setup kan de exacte API-route verschillen; test dit eerst met ongevaarlijke `AI -` testflows.

`HOMEY_TRANSPORT=local` is bewust hard afgedwongen: cloud-hosts zoals `api.athom.com` en publieke IP-adressen worden geweigerd als runtime endpoint. OAuth2 mag later alleen worden gebruikt om een sessie/token te verkrijgen; de uiteindelijke Homey API-calls moeten lokaal naar `HOMEY_BASE_URL` blijven gaan.

Voor de latere OAuth2/session route zijn deze variabelen alvast gereserveerd:

```env
HOMEY_AUTH_MODE=oauth2_session
HOMEY_OAUTH_CLIENT_ID=
HOMEY_OAUTH_CLIENT_SECRET=
HOMEY_OAUTH_REDIRECT_URI=http://10.5.1.150:18080/homey/oauth/callback
HOMEY_OAUTH_REFRESH_TOKEN=
HOMEY_OAUTH_ACCESS_TOKEN=
```

In `oauth2_session` mode gebruikt de proxy de Homey Web API alleen voor authenticatie:

1. bestaande `HOMEY_OAUTH_ACCESS_TOKEN` gebruiken, of een refresh token omwisselen voor een cloud access token;
2. delegation token aanvragen met audience `homey`;
3. met dat delegation token lokaal inloggen op `HOMEY_BASE_URL/api/manager/users/login`;
4. alle daarna volgende manager API-calls lokaal uitvoeren met de lokale session token.

De runtime guard blijft actief: `HOMEY_BASE_URL` mag niet naar Athom/Homey cloud wijzen. Een access token is vooral handig voor tijdelijk testen; voor langdurig draaien is een refresh token met OAuth2 clientgegevens nodig.

OAuth2 bootstrap via de proxy:

1. Maak of open je Homey Web API Client.
2. Zet de redirect URI op `http://10.5.1.150:18080/homey/oauth/callback`.
3. Zet in Dockhand: `HOMEY_AUTH_MODE=oauth2_session`, `HOMEY_OAUTH_CLIENT_ID`, `HOMEY_OAUTH_CLIENT_SECRET` en `HOMEY_OAUTH_REDIRECT_URI`.
4. Redeploy de stack.
5. Haal de autorisatie-url op:

```bash
curl -H "X-API-Key: jouw-proxy-api-key" http://10.5.1.150:18080/homey/oauth/authorize-url
```

6. Open `authorization_url` in je browser en keur toegang goed.
7. De callback geeft `HOMEY_OAUTH_REFRESH_TOKEN` en `HOMEY_OAUTH_ACCESS_TOKEN` terug. Zet deze waarden in Dockhand en redeploy opnieuw.
8. Test daarna:

```bash
curl -H "X-API-Key: jouw-proxy-api-key" "http://10.5.1.150:18080/homey/readiness?live=true"
```

## Veilig testen

Begin altijd met `HOMEY_USE_MOCK=true`. Test daarna alleen met een ongevaarlijke flow zoals `AI - Presence test`. Voeg pas extra flows toe wanneer je zeker weet dat ze veilig zijn.

Veilige live-testvolgorde:

1. Zet `HOMEY_BASE_URL=http://10.5.2.201`.
2. Laat `HOMEY_TRANSPORT=local` staan.
3. Vul een geldige Homey auth mode in.
4. Controleer `GET /homey/readiness`.
5. Zet pas daarna `HOMEY_USE_MOCK=false`.
6. Test `GET /homey/readiness?live=true`.
7. Test daarna pas `POST /homey/command` met `{"command":"test presence"}`.

## Tests draaien

Lokaal met Python:

```bash
pip install -r requirements-dev.txt
pytest
```

Of via Docker:

```bash
docker compose run --rm homey-ai-proxy pytest
```

## GitHub Issues gebruiken

Gebruik GitHub Issues om bugs, wensen en vervolgstappen bij te houden. Maak per onderwerp een losse issue, bijvoorbeeld Docker Compose setup, Homey-client integratie, caching of security allowlist. Beschrijf bij bugs welk endpoint je aanriep, welke config je gebruikte zonder secrets, en wat je verwachtte.

## Bekende beperkingen

- OpenAI tool/function calling staat nog achter de feature flag en is nog niet actief.
- De echte Homey API-routes kunnen per Homey-versie of tokenmethode verschillen.
- Er is nog geen authenticatie op de proxy zelf; zet de service niet publiek open zonder reverse proxy, TLS en toegangscontrole.

## Vervolgstappen

- Proxy-authenticatie toevoegen.
- OpenAI tool/function calling toevoegen met vaste veilige intents.
- HomeyScript-ondersteuning uitbreiden.
- Meer integratietests toevoegen.
- Metrics of dashboard toevoegen voor rate limiting, cache en acties.
