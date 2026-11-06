param([string]$ProfilesRoot = "$env:APPDATA\Thunderbird\Profiles")

$targets = Get-ChildItem $ProfilesRoot -Directory |
    ForEach-Object { Join-Path $_.FullName 'Mail'; Join-Path $_.FullName 'ImapMail' } |
    Where-Object { Test-Path $_ }

foreach ($path in $targets) {
    $acl  = Get-Acl -Path $path -Audit
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        'Everyone',          # S-1-1-0. НЕ "ALL APPLICATION PACKAGES" (S-1-15-2-1) - см. README 2.4
        'ReadData',          # бит 0x1: ReadData для файла
        'ObjectInherit',
        'InheritOnly',
        'Success')
    $acl.AddAuditRule($rule)
    Set-Acl -Path $path -AclObject $acl
    Write-Host "SACL set: $path"
}
