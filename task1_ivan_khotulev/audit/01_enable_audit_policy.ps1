auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable

auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord

wevtutil sl Security /ms:268435456