# SecAuditTool

Passiv sikkerhedsaudit af hjemmesider med lokal web-UI, til rapporter til kunder.
Passive web security auditor with a local web UI, built for customer reports.

## Kør / Run

    python3 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt
    python3 audit.py --port 8080            # åbn http://127.0.0.1:8080

Valgfrit / options: `--allow-private` (scan LAN/localhost), `--rate 5` (max forespørgsler/sek.),
`--scanner-ip 203.0.113.7` (din offentlige IP, vises i rapporten så kunden kan genkende trafikken).
`export NVD_API_KEY=...` giver hurtigere CVE-opslag (gratis nøgle fra nvd.nist.gov).
Slet `audit_results.db`, hvis du opgraderer fra en ældre version (skemaet er ændret).
Tests: `pip install -r requirements-dev.txt && python -m pytest`

## Hvad testes
IPv6 · DNSSEC · HTTPS/HSTS · TLS (versioner, ciphers, certifikat, OCSP, renegotiation, kompression) · DANE ·
security headers · cookies · security.txt · teknologi- og versionsgenkendelse · CVE-opslag (NVD, CISA KEV) og
sårbare JS-biblioteker (OSV + indbygget tabel) · eksponerede filer (.env, .git, backups, phpinfo, logs ...) ·
directory listing · CORS · HTTP-metoder · mixed content · formularer/CSRF · SRI · tredjeparts-scripts/trackere ·
WordPress (xmlrpc, bruger-opregning, plugins) · fejlsider · subdomain takeover · SPF/DMARC/MTA-STS/TLS-RPT/DKIM/STARTTLS.

## Profiler
| Profil | Sider | Stier | Cipher-test | Ekstra |
|---|---|---|---|---|
| quick | 1 | ingen | nej | – |
| standard | 15 | ~35 almindelige | ja | takeover |
| thorough | 30 | ~50 + mapper | ja | DKIM, parameter-refleksion |

## Rapporter
Knapper i UI'et, eller `GET /api/scans/{id}/report.html|md|json?lang=da|en&compare={ældre scan-id}`.
HTML-rapporten er print-venlig: åbn den i browseren og vælg *Udskriv → Gem som PDF*.
Med `compare` får rapporten et før/efter-afsnit.

## Tilføj en ny test
1. Tilføj en nøgle i `knowledge/findings.yaml` (en + da) og en fejl-titel i `knowledge/fail_titles.yaml`.
2. Kald `add(out, ok, "din_nøgle", evidence, ...)` i et modul i `checks/` (`run(target, ctx)`), og registrér det i `PIPELINE` i `app/scanner.py`.
3. `pytest` fejler, hvis en nøgle mangler tekst.

## Forbehold
Passiv konfigurationsaudit, ikke en penetrationstest. Fund kan være falske positiver; versioner er aflæst udefra
(distributionspakker kan have bagudporterede rettelser). Scan kun systemer, du ejer eller har skriftlig tilladelse til at teste.
UI'et har ingen login: bind det kun til 127.0.0.1.
