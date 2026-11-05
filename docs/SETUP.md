# Purple Team Lab – Atomic Red Team / CALDERA × Splunk

Home lab to emulate adversary techniques and prove that the Splunk detections in
[splunk-detection-as-code](https://github.com/Jka667/splunk-detection-as-code) fire, before and after tuning.

```
 Windows VM (Sysmon + Security audit + Splunk UF) ──┐
 Ubuntu VM  (auth.log + Splunk UF)  ────────────────┼──> Splunk (free license) <── check_detections.py
 AWS free tier (CloudTrail -> Splunk Add-on for AWS)┘            ▲
 Atomic Red Team / CALDERA / Stratus Red Team ───── emulate ─────┘
```

## Setup

1. **Splunk**: Splunk Enterprise (free license) on a VM or Docker (`splunk/splunk`). Create indexes
   `sysmon`, `wineventlog`, `linux`, `aws`. Install *Splunk Add-on for Sysmon*, *Splunk Add-on for
   Microsoft Windows*, *Splunk Add-on for Unix and Linux*, *Splunk Add-on for AWS*.
2. **Windows VM**: install [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) with the
   [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) config; enable
   `auditpol /set /subcategory:"Other Object Access Events" /success:enable` (Security 4698); install the
   Universal Forwarder with `inputs.conf` for `Microsoft-Windows-Sysmon/Operational` → `index=sysmon` and
   `Security` → `index=wineventlog`.
3. **Atomic Red Team** on the Windows VM (snapshot it first, run as admin, Defender exclusions for the lab):
   ```powershell
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
   Install-AtomicRedTeam -getAtomics
   ```
   Check test names with `Invoke-AtomicTest T1059.001 -ShowDetailsBrief` and adjust `emulation-plan.csv` if needed.
4. **Ubuntu VM**: forward `/var/log/auth.log` as `sourcetype=linux_secure` → `index=linux`.
5. **AWS (optional)**: CloudTrail trail → S3 → Splunk Add-on for AWS → `index=aws`. Emulate with
   [Stratus Red Team](https://stratus-red-team.cloud/): `stratus detonate aws.persistence.iam-backdoor-user`
   then `stratus cleanup`.
6. **CALDERA (optional)**: run [MITRE CALDERA](https://github.com/mitre/caldera), deploy a Sandcat agent on
   the Windows VM and run the *Discovery* / *Credential Access* adversary profiles; log each ability's
   technique and time in a results CSV with the same columns as below.

## Run an exercise

```powershell
.\scripts\Run-PurpleTest.ps1 -Cleanup          # writes results\run-<timestamp>.csv
```
```bash
pip install pyyaml
export SPLUNK_TOKEN=<token>
python scripts/check_detections.py results/run-<timestamp>.csv --splunk https://<splunk>:8089 --insecure
```

`check_detections.py` runs each detection's SPL over the test window and writes `results/run-<timestamp>.md`
(DETECTED / MISSED). Manual tests (SSH brute force with hydra, AWS, Office macro) are added as extra rows in
the results CSV with their UTC times.

Write up each exercise with [reports/TEMPLATE.md](../reports/TEMPLATE.md): gaps become Jira tickets and
rule changes in splunk-detection-as-code (before / during / after the exercise).

> Only run these tests on lab machines you own. Snapshot VMs before each run.
