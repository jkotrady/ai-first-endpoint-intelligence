# Vytvorenie a interné vydanie nového zberu

Cieľ je auditovateľný allowlist, spoločný pre web/API/AI a endpoint. Agent
pravidelne iniciuje odchádzajúce TLS spojenie (pilot približne5s + čas requestu),
preberá úlohy viazané na svoju identitu a nahráva výsledok. Agent nepočúva na
sieťovom porte. Cloudový model neposiela shell ani programový kód do agenta.

## Postup vývojára

1. Vyberte ID z plánu50zberov. `python3 scripts/new-collector.py F03` vytvorí
   `collectors/drafts/F03/` so zdrojom, fragmentom katalógu a review poznámkami.
   Draft sa nekompiluje, nezobrazuje v API a nič nepublikuje.
2. Doplňte konkrétnu implementáciu iba cez potrebné read-only API, explicitné
   limity a `error`/`partial`. Nepridávajte interpreter, všeobecný process runner
   ani svojvoľné parametre. Parametrizované zbery potrebujú samostatnú verziovanú
   schému a validáciu na serveri aj agente; dnešné4zbery nemajú vstupné parametre.
3. Po review presuňte C súbor do `collectors/windows/` a pridajte schválený záznam
   do `collectors/catalog.json`. Odstráňte draft placeholder; nesmie sa tváriť ako
   implementovaná capability. Windows API podporu overte aj reálnym XP/7 behom.
4. `sh scripts/build-agent.sh` generuje native dispatch, zdrojový ZIP a manifest.
   `sh scripts/check.sh` overí API/AI/tenant pravidlá, balenie a syntaktické chyby.
   Manuálny dropdown a AI allowlist používajú rovnaký katalóg. Pre novú
   sémantiku doplňte výsledkový kontrakt, testy a AI opis; nestačí prepísať názov.
5. Pre každý zmenený collector uložte runtime protokoly s hashom konkrétneho EXE.
   Testujte všetky požadované OS, oprávnenia, Unicode, limity a chyby. Staršie
   protokoly nie sú automaticky dôkaz nového buildu.
6. `python3 scripts/stage-agent-release.py pilot-YYYYMMDD-N` zmrazí lokálnu
   nemennú kópiu do `work/releases/`. Existujúci názov odmietne prepísať. Nejde
   o produkčné publikovanie ani podpisový release gate.
7. V control centre stiahnite **Aktualizácia agenta**. Balík nemá zákaznícky
   token ani zdrojový kód; obsahuje EXE, notices, manifest a manuálny postup. Na skúšobnom
   endpointe zastavte starý foreground agent, overte hash a vymeňte iba EXE.
   Zachovajte jeho agent.conf/ca.pem a ACL. Aktualizácia sa sama nevykonáva.

## Autorizácia a verzia

Webové schválenie používa `/api/jobs/approve` s customer_id, device_id,
collector_id a agent_source (fingerprint zo zobrazeného endpointu). Server
vyžaduje session+same-origin, customer grant, vlastný aktívny endpoint,
allowlist, jeho ohlásenú capability a zhodu verzie. Pri zmene verzie treba
obnoviť prehľad a znovu schváliť. Starý `/api/jobs` zostáva iba pre agentov bez
verziového hlásenia; na novom agentovi nemôže obísť version pin.

Úloha uloží verziu. Poll ju doručí iba rovnakej verzii ako `JOB2 … source_hash`;
agent porovná hash so svojím skompilovaným fingerprintom pred dispatchom.
AI návrh nesie tú istú verziu, kontrolovanú aj po návrate z providera. AI
nevytvára úlohu sama. Každá úloha/výsledok zostáva customer-scoped a auditovaná.

To nie je podpísaná job obálka ani atestácia kompromitovaného endpointu.
Token/session ochrany a version pin sú pilot; finálne RBAC/OIDC, podpisy,
rotation/revocation a plný bezpečnostný audit majú vlastné úlohy v backloge.

## Samostatné balíky bez výmeny EXE

Používateľ chce jednoduché publikovanie jednotlivých zberov. Dnešný natívny
pilot rozširuje zbery novým EXE. Podľa R21 preferujeme samostatné malé C executable collectory
kompatibilné s XP/7. Návrh je v docs/COLLECTOR-PACKAGES.md. Pred implementáciou treba
riešiť podpisový trust root, hash/verziu schváleného balíka, schémy/limity,
replay/rollback ochranu, tenant publish práva, audit a odvolanie balíka.
Samotný upload súboru ani odpoveď AI nikdy nie sú oprávnenie k spusteniu.
