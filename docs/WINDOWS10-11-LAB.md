# Windows 10/11 — konkrétna príprava laboratória

Profily `tools/lab/modern-windows.json` zachovávajú W04–W12 z výberovej matice.
Win10: Pro22H2 x86/x64, Enterprise LTSC2019 a2021 x86/x64. Win11: Pro25H2,
Enterprise25H2/24H2 x64. Home ani verejná26H2 nenahrádzajú tieto bunky.

`python3 tools/modern_lab.py` číta médiá a vytvorí preflight report. Nič nesťahuje,
nespúšťa VM, nemení hosta ani nevypína kontroly Windows. BIOS/TCG/2CPU/4GiB/64GiB
Win10 je oddelený od Win11 q35/KVM/UEFI Secure Boot/vTPM2.0/4CPU/8GiB/96GiB.
Na aktuálnom hoste sú QEMU a OVMF s Microsoft enrolled vars; chýba `/dev/kvm`
a `swtpm`. Win11 launcher so životným cyklom TPM/privátnymi UEFI vars ešte treba
implementovať a otestovať; dnešný Win7 BIOS launcher sa naň nepoužije.

## Prijatie média

ISO uložiť do `work/lab/media/`. Pre každý profil vytvoriť
`work/lab/modern-manifests/W04.json` (príklad štruktúry, hodnoty doplniť podľa
skutočného zdroja, nie z tohto príkladu):

```json
{
  "product_edition": "Windows 10 Pro",
  "version": "22H2",
  "build_family": "10.0.19045",
  "architecture": "x86",
  "image": "work/lab/media/windows10-22h2-x86.iso",
  "sha256": "SEM_NEZAVISLE_OVERENY_SHA256_ZDROJA",
  "size": 0,
  "source_reference": "Presná oficiálna stránka/hash dokument alebo licencia média"
}
```

Chybná veľkosť, hash, edícia/architektúra alebo cesta mimo projektu blokuje export.
Súlad s manifestom je kontrola bajtov a zadaných tvrdení; **neoveruje obsah WIM,
licenciu ani skutočne nainštalovanú edíciu**. Tie treba zaznamenať samostatne.
EULA Windows7/10/11 už používateľ schválil (R18), nežiadať znovu.

Po úspešnom intake Win10: `python3 tools/modern_lab.py --export-profile W04`.
Výsledok `work/lab/verified-w04.json` je vstup pre
`python3 tools/windows_lab_console.py --profile work/lab/verified-w04.json`.
Pred inštaláciou overiť voľnú host RAM a ponechať aspoň2GiB hostu; bežať vždy
jednu VM. Vybrať Pro/LTSC presne podľa cieľa, zaznamenať winver/architektúru/edíciu,
patch inventory a checkpoint. Bez aktivácie nehlásiť aktivovaný OS.

## Agentové skúšky po inštalácii

- Offline vytvoriť privátne heslo, vyhradený C:\pilot a ACL; overiť ich aj na EXE.
- Distribuovať konkrétny EXE + manifest; uložiť jeho SHA-256 a `--list`/`--version`.
- Na x64 otestovať x86 kandidáta cez WoW64; natívny x64 agent zatiaľ neexistuje.
- Otestovať F01/F04/F08/F15, Unicode, neprivilegovaný účet, partial/denied,
  F99, TLS name/CA/token, restart/retry a zákaz zberu nepodporovaného agentom.
- Až potom skúsiť riadený API tok cez explicitne obmedzenú lokálnu TLS bránu.
  Predvolená sieť zostáva vypnutá. Uložiť výsledky pre každé W-ID samostatne.

Aktuálne médium pre žiadnu z W04–W12 buniek nemáme. Predošlé Microsoft Win10
API vrátilo403; príjem overeného média je pripravený, download obmedzenie sa
neobchádza. LTSC/Enterprise treba z oprávneného organizačného alebo subscription
zdroja. Používateľov Win10Home OEM kľúč nenahrádza Pro/LTSC licenčný podklad.

[Microsoft Windows11 požiadavky](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements)
uvádzajú UEFI/Secure Boot capability, TPM2.0 a podporovaný procesor. Hostový
preflight nepotvrdzuje správne nastavenie vo vnútri VM; to vyžaduje runtime dôkaz.
