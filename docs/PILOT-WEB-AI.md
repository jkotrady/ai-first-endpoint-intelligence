# Web, registrácia a AI — interný pilot 0.2

## Ako začať

Lokálny web beží na http://127.0.0.1:8080/. Verejná úvodná stránka je `/`, prihlasovací portál `/portal`, registrácia `/register`, ovládacie centrum `/control`. Žiadna zmena nepublikuje službu na internet.

Prvý účet `operator` už existuje. V súkromnom súbore `work/pilot/first-login.txt` nájdite meno, heslo a riadok **TOTP secret**. V Google Authenticator zvoľte **+ → Zadať kľúč nastavenia**, názov napríklad Forensics, vložte celý TOTP secret a vyberte **Časový** typ. V Microsoft Authenticator použite **Iné konto → manuálne zadanie**. Následne do portálu zadajte aktuálny šesťmiestny kód z telefónu. Kód sa mení každých 30 sekúnd. Hash a salt zo state.json do autentifikátora nepatria. Telefón musí mať automatický dátum a čas. Podrobný návod je priamo na `/setup`.

Prihlásený tester vytvorí v prehľade pozvánku. Jednorazový odkaz je platný 24 hodín a jeho tajná časť je v URL fragmente. Nový tester si vyberie meno a heslo (aspoň 14 znakov), uloží zobrazený TOTP secret a do 10 minút overí kód. Až potom vznikne účet a vlastný oddelený zákaznícky priestor. Päť chybných overení zruší pozvánku. Opakované otvorenie už začatého nastavenia nezobrazí secret; dokončite pôvodnú kartu alebo po 10 minútach začnite znova. Pozvanie nedáva prístup k dôkazom pozývajúceho.

Ide o miestne účty pre najviac 10 testerov, bez emailov, obnovy MFA, OIDC/SSO či produkčného onboarding procesu. Súkromný serverový stav musí zostať dostupný iba vlastníkovi. Existujúce účty aj výsledky sa pri aktualizácii zachovávajú; sessions sa pri reštarte rušia.

## Ovládanie agenta

V control centre vyberte zákazníka. Pridanie endpointu stiahne ZIP s vlastnou identitou agenta; používajte ho iba pre tento endpoint. Aktuálny gateway je laboratórny, nie verejný internetový enrollment. Spustite `run.cmd` v chránenom priečinku na Windows. Web zobrazuje skutočný hostname, IP a posledný kontakt. Online znamená kontakt za posledných 60 sekúnd.

Vyberte F01 (identita), F04 (procesy) alebo F08 (IPv4 TCP/PID) a potvrďte zber. Agent prevezme úlohu, vykoná collector a uložený výsledok nájdete v Zberoch. Odvolaný agent prestane mať prístup. Audit zaznamenáva schválenie, doručenie a prijatie výsledku.

## AI asistent

Na karte AI asistent vložte vlastný OpenAI API kľúč a presné ID modelu dostupného vo vašom API účte, ktorý podporuje Responses/function calling. Predplatné ChatGPT nie je API kredit. Kľúč sa používa iba v pamäti stránky a serverovej požiadavky; nie je v localStorage, súboroch, auditných udalostiach ani provider inpute. Obnovenie stránky ho vymaže. Tento lokálny pilot nie je E2EE: server vidí požiadavku aj vybraný plaintext dôkaz.

Potvrdený rozsah odoslania zahŕňa otázku, inventár aktívnych zariadení práve vybraného zákazníka a najviac jeden explicitne vybraný dokončený výsledok (do 32 KiB). Každá otázka je samostatná; viditeľná história chatu sa neposiela. Bez súhlasu sa externé API nevolá. Endpoint providera je pevný `https://api.openai.com/v1/responses`, bez presmerovaní; `store:false`, 45-sekundový timeout, maximálne 1600 output tokenov, 5 požiadaviek/minútu/používateľa, najviac 2 súbežné. `store:false` nenahrádza retenčné podmienky poskytovateľa.

Model môže vrátiť text alebo jeden typovaný návrh `propose_collection(device_id, collector_id, reason)`. Server odmietne cudzí endpoint, iný collector, dodatočné/duplicitné argumenty a odvolaný prístup. Model nemá nástroj na priamu exekúciu. Tlačidlo **Schváliť a spustiť zber** volá existujúce autorizované `/api/jobs`. Návrh nie je dôkaz, že zber prebehol. Po dokončení vyberte výsledok a požiadajte o analýzu. Obsah dôkazov sa považuje za nedôveryhodný; zobrazovanie používa textContent.

Priamy konektor ChatGPT cez MCP/OAuth a Claude adaptér ešte nie sú implementované. Implementované OpenAI volanie má lokálne testy s falošným HTTP transportom; živý cloud test nie je vykonaný bez používateľského API kľúča. Ak provider zlyhá, zber sa nespustí a jeho surové chyby sa nevracajú do UI.

## Overenie a referencie

Go testy pokrývajú registráciu/MFA/replay/izoláciu, AI rozsah a súhlas, návrh bez exekúcie, odmietnutie nebezpečných argumentov, odvolanie/session zmenené počas provider volania, limit a redakciu chýb. HTTP report: `outputs/web-redesign-http-2026-10-13.json`. Go race testy ani HTTP kontrola nenahrádzajú vizuálny browser test; ten zostáva neoverený kvôli predchádzajúcemu odmietnutiu browser nástroja bezpečnostnou politikou.

Oficiálna dokumentácia overená 13. 10. 2026: [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling), [TOTP Key URI format](https://github.com/google/google-authenticator/wiki/Key%20Uri%20Format). Vizuálne referencie: [SentinelOne](https://www.sentinelone.com/), [CrowdStrike](https://www.crowdstrike.com/en-us/); vlastná značka, grafika a texty. Banner Free je stále lokálny placeholder bez reklamnej siete a sledovania.

Dodatočný regresný test overuje rollback zlyhaného vytvorenia pozvánky: pri chybe zápisu sa stav obnovuje do novej štruktúry, aby JSON pole vynechané cez omitempty nemohlo ponechať nepotvrdenú pozvánku v pamäti.
