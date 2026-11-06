param([string]$ProfilesRoot = "$env:APPDATA\Thunderbird\Profiles")

"== Audit policy"
auditpol /get /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}"
auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}"

"== SACL"
Get-ChildItem $ProfilesRoot -Directory | ForEach-Object {
    foreach ($d in 'Mail','ImapMail') {
        $p = Join-Path $_.FullName $d
        if (Test-Path $p) { $p; (Get-Acl $p -Audit).Audit | Format-Table IdentityReference,FileSystemRights,InheritanceFlags,PropagationFlags,AuditFlags -AutoSize }
    }
}

"== Functional test: read one mbox and look for 4663"
$f = Get-ChildItem $ProfilesRoot -Recurse -File | Where-Object { $_.FullName -match '\\(Mail|ImapMail)\\' } | Select-Object -First 1
$t = Get-Date
[void][IO.File]::ReadAllBytes($f.FullName)
Start-Sleep 2
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=$t} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[6].Value -eq $f.FullName } | Select-Object -First 1 | Format-List TimeCreated,Message
