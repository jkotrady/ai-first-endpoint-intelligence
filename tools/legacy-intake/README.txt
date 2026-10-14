AI-first forensics - legacy lab intake 0.1.0
EXPERIMENTAL: NOT YET RUN ON WINDOWS XP OR WINDOWS 7.

Purpose
  Local lab inventory, not a production agent or forensic collection tool.
  It reads selected local WMI properties: OS caption/version/service pack,
  CPU architecture/address width, visible/free RAM, locale/timezone offset,
  and drive letter/filesystem/capacity/free space of fixed logical drives.
  It does not request product keys, serial numbers, accounts, files,
  process lists, hostname, IP addresses or remote access credentials.
  Hardware/OS metadata can still be sensitive. Inspect output before sharing.

Before running
  Use only your authorized test laptop/VM, on an isolated lab network or
  offline. Keep an independently restorable baseline. Use a normal account
  first; do not disable security policy or antivirus to run this kit.
  Unzip the entire kit into a NEW local fixed-disk directory, e.g.
  C:\forensics-intake. Do not run directly in the ZIP or on a network share.
  A mapped network drive or removable drive is also rejected.

Run
  Double-click run.cmd or launch it from an existing Command Prompt:
    cd /d C:\forensics-intake
    run.cmd

  The wrapper invokes the Windows Script Host at its SystemRoot path,
  without PowerShell, WMIC, Python, downloads, or remote commands.
  It sets a 60-second script-host timeout. If Windows Script Host/VBScript
  or WMI is unavailable, stop and record that fact. Do not enable them
  automatically. Modern Windows are not this kit's target.

Output
  result\observations.txt (UTF-16 with BOM) is created next to the script.
  Existing result directories are NEVER overwritten. Use a fresh kit
  directory for each run and keep the previous result for comparison.
  Exit 0 = all selected queries completed; NOT verified OS/agent support.
  Exit 2 = partial WMI observations; inspect missing/error records.
  Exit 3 = unavailable host, bad location, existing result, write failure,
           blocked script, script error or timeout.
  If interrupted, an absent end=complete marker means an incomplete run.
  Timeout stops the script host; provider-side WMI work may end later.

  The script does not change system configuration. Creating its output
  and ordinary WMI/OS logging still change disk state. This is not a
  zero-impact acquisition, performance benchmark or malware-clean bill.
  Data from a compromised endpoint may be false even when exit code is 0.

Next
  Copy only observations.txt to the modern project host under
  work/lab/intake/<your-lab-run-id>/; do not send license keys.
  Import with the project's tools/import_legacy_intake.py (Python 3.10+).
  The resulting JSON always requires human review. It never proves
  edition, license, isolation, patch completeness, or agent compatibility.
  It is not an image manifest and must not go into work/lab/manifests.

Integrity
  SHA256SUMS.txt identifies the three payload files. Verify on the modern
  trusted host before transfer. A hash list is not a digital signature
  and is not proof of the source if an attacker can replace both files.

Cleanup
  After preserving/reviewing the result, remove only the extracted kit
  directory when no longer needed. There is no installed service or task.
