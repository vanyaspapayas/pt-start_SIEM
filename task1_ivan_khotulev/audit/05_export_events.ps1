param(
    [Parameter(Mandatory)][datetime]$From,
    [Parameter(Mandatory)][datetime]$To,
    [Parameter(Mandatory)][string]$Name,          # например attack_copy / attack_bulk / legit_thunderbird
    [string]$OutDir = "$PSScriptRoot\..\events"
)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$f = $From.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
$t = $To.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.999Z')
$time = "TimeCreated[@SystemTime>='$f' and @SystemTime<='$t']"

wevtutil epl Security "$OutDir\${Name}_Security.evtx" /q:"*[System[(EventID=4663 or EventID=4688) and $time]]" /ow:true
wevtutil epl Microsoft-Windows-Sysmon/Operational "$OutDir\${Name}_Sysmon.evtx" /q:"*[System[$time]]" /ow:true
Get-ChildItem $OutDir -Filter "$Name*"

# Пример:
# .\05_export_events.ps1 -From '2026-11-05 14:00' -To '2026-11-05 14:05' -Name attack_copy
