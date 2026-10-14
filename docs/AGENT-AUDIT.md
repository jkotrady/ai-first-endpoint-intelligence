# Audit zdrojov a konkrétneho EXE

1. Prečítajte `collectors/catalog.json` a zodpovedajúce `collectors/windows/F*.c`.
   `registry.c` tvorí jediný dispatch; `agent/windows/agent.c` obsahuje transport.
2. Zdrojový ZIP je lokálny release artefakt pre budúce publikovanie v GitHube,
   nie download v GUI. Cieľový repozitár je
   https://github.com/jkotrady/ai-first-endpoint-intelligence. Podpísaný release
   ešte nie je vydaný.
   Build manifest v GUI obsahuje iba metadata/hashes. Zdrojový ZIP má iba
   explicitne vybrané projektové zdroje, build skripty, pin závislostí a notices.
   Neobsahuje agent.conf, tokeny, dôkazy, Windows médiá ani licenčné kľúče.
3. Porovnajte SHA-256 nasadeného `forensics-agent.exe` s `binary_sha256` v manifeste.
   EXE `--list` zobrazí skompilovaný katalóg a `--version` fingerprint build vstupov (.c/.h/.py/.sh/.json z manifestu; docs a notices
   majú samostatné file hashe a nemenia EXE verziu). Tieto reťazce aj HTTP hlásenie agenta sú vlastné tvrdenia programu,
   nie vzdialená kryptografická atestácia.
4. Na Ubuntu amd64 rozbaľte zdroje do samostatného pracovného adresára. Spustite
   `python3 scripts/bootstrap-agent.py` a `sh scripts/build-agent.sh`. Piny sú v
   `outputs/pilot-toolchain-2026-10-13.json`; chýbajúca presná verzia je chyba.
   Závislosti Mbed TLS/MinGW sa získavajú samostatne podľa pinov, nie z Windows VM.
5. Porovnajte výsledný hash. Deterministický build sa overuje opakovaním; zhoda
   na jednom hoste ešte nie je dôkaz reprodukovateľnosti na nezávislom hoste.

Manifest spája každý zdrojový súbor, katalóg, zdrojový ZIP a výsledné EXE hashmi.
Server pri sťahovaní binárky/enrollmente odmietne nesúlad artefaktov.
GUI a jeho ZIP balíky neobsahujú zdrojový kód (R21). Nejde o podpísaný
release manifest, Authenticode, bezpečnostný audit toolchainu ani absolútny dôkaz,
že napadnutý endpoint spúšťa práve tento program. Tieto release gates ostávajú.
Po aktualizácii agent hlási capability pri každom poll; starý agent má iba pôvodné
F01/F04/F08. API aj AI odmietnu zber, ktorý daný endpoint nehlási.

F15 API referencia: [EnumServicesStatusExW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw),
[QueryServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw).

Úlohy nového agenta používajú version pin (agent_source/JOB2); server a agent
odmietnu vykonanie pod inou hlásenou zdrojovou verziou. Postup rozšírenia je
v docs/COLLECTOR-AUTHORING.md v projektovom repozitári.
