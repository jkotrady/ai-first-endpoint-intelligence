# Natívne forenzné collectory

Každá implementovaná akcia má samostatný súbor v `windows/` a explicitné ID v
`catalog.json`. Nie sú to PowerShell skripty: pre XP sa kompilujú priamo do EXE.
Priečinok sa na endpointe neprehľadáva a vložený `.ps1`, `.bat`, DLL alebo C súbor
sa nespustí. `registry.c` dispatchuje iba funkcie z katalógu; ID mimo zoznamu
vráti `collector_not_allowed`. `runtime.c` poskytuje ohraničený JSON výstup.

Transport/TLS, konfigurácia, retry a lokálny stav sú v `agent/windows/agent.c`.
Zbery nespúšťajú podprocesy. `run.cmd` v privátnom enrollment ZIP je iba viditeľný
štartér agenta. Laboratórne provisioning skripty v `tools/` a `work/` nie sú
produktové collectory.

F01/F04/F08 sú stále čiastkové implementácie širšieho katalógu 50 akcií.
F15 číta Win32 služby viditeľné aktuálnemu účtu; nemá právo meniť konfiguráciu,
spustiť alebo zastaviť službu. Účet a binary path môžu obsahovať citlivé údaje.
API môže neviditeľné služby vynechať bez chyby; `complete` znamená dokončenie
tejto ohraničenej enumerácie, nie úplný inventár všetkých služieb systému.

Zdrojový audit a porovnanie konkrétneho buildu: `docs/AGENT-AUDIT.md`.
