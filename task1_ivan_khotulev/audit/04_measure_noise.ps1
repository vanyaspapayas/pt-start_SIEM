param([double]$Hours = 1)
$ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=(Get-Date).AddHours(-$Hours)} -ErrorAction SilentlyContinue |
      Where-Object { $_.Properties[6].Value -match '\\Thunderbird\\Profiles\\' }
# Индексы полей 4663: 6=ObjectName, 9=AccessMask, 10=ProcessId, 11=ProcessName
"Всего событий: {0} за {1} ч ({2:N0}/ч)" -f $ev.Count, $Hours, ($ev.Count / $Hours)
$ev | Group-Object { $_.Properties[11].Value } | Sort-Object Count -Descending |
      Format-Table Count, Name -AutoSize
