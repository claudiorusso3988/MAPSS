Microservices Anti-Pattern Security Scanner

Framework modulare di Static Code Analysis scritto in Python, progettato per rilevare anti-pattern architetturali e vulnerabilità di sicurezza in ecosistemi a microservizi basati su Java Spring, Docker e Kubernetes.

Lo scanner analizza codice sorgente, file di configurazione e manifest infrastrutturali per individuare configurazioni insicure, cattive pratiche di autenticazione/autorizzazione e problemi di esposizione dei servizi.

🚀 Caratteristiche principali
Architettura modulare basata su plugin
Supporto per progetti Java Spring Boot
Analisi di Dockerfile e manifest Kubernetes
Supporto a scansione di directory locali e archivi .zip
Generazione automatica di report strutturati
Controlli separati per ridurre sovrapposizioni e falsi positivi
📁 Struttura del progetto
progetto_scanner/
│
├── main.py                  # Entry point della CLI
├── scanner.py               # Orchestratore centrale delle scansioni
├── reporter.py              # Gestione della generazione del report
├── utils.py                 # Utility generiche (es. estrazione ZIP)
│
├── analyzers/               # Moduli di analisi (1 per anti-pattern)
│   ├── __init__.py
│   ├── ca.py
│   ├── hs.py
│   ├── iac.py
│   ├── mua.py
│   ├── nde.py
│   ├── nsc.py
│   ├── pam.py
│   ├── uptm.py
│   └── ut.py
│
└── reporters/               # Formatter del Report.txt
    ├── __init__.py
	├── report_CA.py
    ├── report_HS.py
    ├── report_IAC.py
    ├── report_MUA.py
    ├── report_NDE.py
    ├── report_NSC.py
    ├── report_PAM.py
    ├── report_UPTM.py
    └── report_UT.py
	
⚙️ Requisiti
Python 3.8 o superiore
📦 Installazione

Clona la repository:

git clone <repository-url>
cd progetto_scanner

Installa le dipendenze:

pip install -r requirements.txt
💻 Utilizzo

Il tool può analizzare:

una directory locale contenente un progetto a microservizi
un archivio .zip (estratto automaticamente)
Scansione di una directory
python main.py /percorso/del/progetto_microservizi
Scansione di un archivio ZIP
python main.py /percorso/del/progetto.zip
📄 Output

Al termine della scansione verrà generato un file:

Report.txt

contenente:

anti-pattern rilevati
file coinvolti
dettagli delle anomalie
informazioni contestuali utili all’analisi
🔍 Anti-pattern e vulnerabilità analizzati
OCC — Own Crypto Code

Identifica implementazioni crittografiche personalizzate o operazioni sospette su array di byte (es. XOR manuali), verificando contemporaneamente l’assenza di librerie standard affidabili come:

BouncyCastle
Google Tink
NSC — Non-secured Service-to-service Communications

Rileva comunicazioni interne non cifrate:

utilizzo di http://
disabilitazione SSL/TLS
Ingress Kubernetes senza HTTPS
NDE — Non-encrypted Data Exposure

Identifica esposizione di dati sensibili:

password in chiaro nei log
query SQL con credenziali hardcoded
utilizzo di protocolli obsoleti come FTP o Telnet
PAM — Publicly Accessible Microservices

Individua microservizi backend esposti pubblicamente tramite:

Kubernetes LoadBalancer
Kubernetes NodePort
regole Ingress eccessivamente permissive
UPTM — Unnecessary Privileges To Microservices

Analizza privilegi eccessivi nei container:

Docker
assenza dell’istruzione USER
esecuzione come root
Kubernetes
privileged: true
runAsUser: 0
HS — Hardcoded Secrets

Rileva credenziali e token cablati nel codice:

AWS Access Key (AKIA...)
token GitHub
JWT statici
variabili come:
password
secret
secret_key
UT — Unauthenticated Traffic

Cerca endpoint esposti senza autenticazione:

uso improprio di .permitAll()
esposizione di rotte sensibili
configurazioni Spring Security troppo permissive
IAC — Insufficient Access Control

Verifica l’assenza di controlli autorizzativi:

controller privi di:
@PreAuthorize
@RolesAllowed
annotazioni RBAC equivalenti
MUA — Multiple User Authentication

Rileva logiche di autenticazione duplicate nei microservizi:

endpoint /login locali
generazione autonoma di JWT
autenticazione decentralizzata

L’autenticazione dovrebbe essere delegata a un Identity Provider centralizzato.

CA — Centralized Authorization

Individua l’anti-pattern opposto a MUA:

API Gateway che gestisce autorizzazioni applicative dettagliate
mapping centralizzati complessi
forte accoppiamento tra gateway e microservizi
🏗️ Architettura del framework

Il progetto segue un’architettura disaccoppiata:

gli analyzer si occupano esclusivamente della scansione
i reporter gestiscono la formattazione dell’output
scanner.py orchestra l’intero processo
main.py espone la CLI

Questo approccio facilita:

estendibilità
manutenzione
aggiunta di nuovi controlli
personalizzazione dei report
📜 Licenza

Distribuito sotto licenza MIT.

Per maggiori dettagli consulta il file LICENSE.