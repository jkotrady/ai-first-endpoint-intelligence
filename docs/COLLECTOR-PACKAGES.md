# R21 — GitHub zdroje a samostatné podpísané C collectory

Stav: návrh a offline prototyp T065. Aktívny pilot stále dispatchuje collectory
zabudované do agenta. Automatické sťahovanie/spúšťanie EXE ešte nie je zapnuté.

## Odporúčaná výsledná podoba

Každá akcia bude samostatný malý natívny program: napríklad `F15.exe` zostavený
z `collectors/windows/F15_services.c` a spoločného ohraničeného JSON runtime.
Na XP/7 netreba Python ani PowerShell. Jeden EXE má jeden pevný entrypoint;
argumenty budú typované údaje, nikdy ďalší program, shell alebo download URL.
Existujúci prototyp F01/F04/F08/F15 nemá vstupné parametre.

GitHub bude obsahovať agent, zdroje collectorov, katalóg, presný build recept,
piny toolchainu/závislostí, testy a review históriu. Zdrojáky sa nezobrazujú ani
nesťahujú cez zákaznícke GUI. Konkrétny release pripne nemenný commit a hash
zdrojového archívu; nikdy `main`, `latest` alebo nezafixovanú závislosť.

CI zostaví konkrétne EXE. Nezávislý rebuild musí vytvoriť rovnaký SHA-256;
provenance/attestation prepojí build so zdrojovým commitom a workflow. Manifest
balíka určí ID/verziu, source commit/hash, build recipe/toolchain hash, EXE hash
+ veľkosť, OS/architektúru, schému argumentov/výsledku a limity. Dôveryhodný
release proces ho podpíše samostatným publikačným kľúčom. Verejný overovací
kľúč sa distribuuje s agentom; zmena trust root potrebuje overenú kontinuitu.
Podpis súboru sám osebe nie je review bezpečnosti jeho zdroja.

GitHub attestation je pôvod build artefaktu, nie dôkaz jeho neškodnosti.
[Oficiálna dokumentácia GitHub](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
opisuje tento druh provenance. Konkrétny workflow a nezávislý rebuild zatiaľ
neprebehli; cieľový repo je https://github.com/jkotrady/ai-first-endpoint-intelligence,
podpisový kľúč a podpísaný release ešte nie sú vytvorené.

## Tok úlohy

1. Prihlásený používateľ v customer tenante vyberie povolené ID/verziu. AI smie
   vytvoriť iba typovaný návrh cez rovnaký policy/executor; nemôže publikovať,
   meniť dôverované kľúče alebo sama schváliť citlivú úlohu.
2. Approval/job pripne tenant, device ID, collector/package SHA-256, kanonické
   argumenty, limity, nonce a expiráciu. Finálna job obálka musí byť podpísaná;
   dnešný JOB2 používa iba TLS/token a source pin, nie tento finálny podpis.
3. Agent odchádzajúcim TLS pollom prevezme iba svoju úlohu. Ak mu balík chýba,
   stiahne presne určený content-addressed artefakt z nášho server mirroru.
   Mirror kopíruje schválené GitHub releases; sám podpis nenahrádza. Endpoint
   nemusí hovoriť priamo s GitHubom ani spoliehať na starý Windows cert store.
4. Agent overí podpis manifestu/jobu, publisher trust, hash/veľkosť balíka,
   revokáciu/verziu, vlastný tenant/device, expiráciu a lokálnu policy. Pri
   chýbajúcom dôkaze alebo nepovolenej verzii nesmie spustiť náhradný balík.
5. Worker spustí overený lokálny EXE cez úplnú `lpApplicationName` cestu,
   bez `cmd.exe`, ShellExecute, PATH vyhľadávania či vložených shell argumentov.
   [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
   je natívny vstup pre proces; potrebnú cestu a handle inheritance treba
   nastaviť explicitne. Samotné CreateProcess nie je bezpečnostná izolácia.
6. Výsledok má verziu collectora, hash vykonaného balíka, job/nonce, časy,
   exit status a ohraničené stdout/JSON. Parent ho validuje, uloží do retry
   fronty a nahrá cez odchádzajúci TLS. Worker nedostane enrollment token.

## Povinné gates pred zapnutím workeru

- App-level podpis overiteľný aj na XP cez pinovanú crypto knižnicu; algoritmus,
  canonical encoding, key IDs, expiry/clock skew, rotation/revocation a downgrade
  politika musia prejsť T006. Windows Authenticode je doplnková ochrana, nie
  jediný trust mechanizmus závislý na starom OS.
- Oddelené download/staging/verified adresáre, ACL, atomický publish a ochrana
  pred výmenou EXE alebo rodičovskej cesty medzi hash kontrolou a štartom
  (TOCTOU). Pred spustením urobiť znovu kontrolu a uzamknúť overený súbor.
  Len otvorenie file handle bez návrhu directory ACL problém úplne nerieši.
- Vlastné prostredie/CWD, žiadne zdedené tajné premenné či otvorené token/CA
  súbory, obmedzené dedenie handles. Windows7 má osobitné správanie štandardných
  handles; XP nemá všetky moderné handle-list API. Otestovať každú cestu.
- Worker začne suspended, priradí sa do podporovaného Job Object, nastaví
  process/memory/time limity a až potom sa spustí. Rodič obmedzí výstup a ukončí
  timeout. [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
  majú OS rozdiely; jeden generický moderný sandbox nemožno vyhlásiť za XP gate.
- Testy: poškodený balík, nesprávny kľúč/hash/tenant, neznámy ID, stará/revokovaná
  verzia, zmena súboru počas štartu, Unicode/space cesty, podproces, pretečenie
  výstupu, timeout/cancel, crash/retry bez dvojitého vykonania a resource záťaž.

## Čo je možné objektívne tvrdiť

Zdroj + pinovaný recept + nezávislý identický rebuild preukazujú väzbu konkrétnej
binárky na zverejnené vstupy. Podpis a agent allowlist určujú, ktoré balíky
normálne fungujúci agent prijme. Audit uloží presný hash schválenej a vykonanej
verzie. To je kontrolovateľnejšie než samotný zoznam názvov skriptov.

Bez dôveryhodného OS nemožno absolútne preukázať, že už kompromitovaný endpoint
nesfalšoval hlásenie alebo nespustil iný program. TPM/remote attestation by bola
samostatná moderná vrstva; nesmie sa sľubovať univerzálne pre XP/7.

## Aktuálny experiment

`python3 scripts/build-collectors.py` vytvorí štyri samostatné x86 EXE do
`work/bin/collectors/` a manifest hashov. Každý EXE sa spúšťa bez argumentov,
`--version` vypíše source fingerprint, iné argumenty vráti exit2. Import guard
odmieta process launch API a nekompatibilné importy. Binárky nie sú podpisované,
agent ich zatiaľ nespúšťa a GUI ich nedistribuuje. Offline VM skúšky sú
samostatným dôkazom; nie sú povolenie zapnúť automatický download executor.
