# Запросы для поиска похожей активности

Поля указаны в двух вариантах: **таксономия MaxPatrol SIEM** (для PDQL после нормализации) и
**KQL** (Microsoft Defender for Endpoint, Advanced Hunting). Синтаксис PDQL приведён в упрощённом виде:
функции поиска по подстроке/шаблону в разных версиях могут отличаться.

## 1. Закодированный скрытый PowerShell от командного файла (этап 2)

PDQL:
```
filter(msgid = "1" and event_src.title = "sysmon"
       and object.process.name = "powershell.exe"
       and object.process.cmdline like "%-enc%"
       and (object.process.cmdline like "%-nop%" or object.process.cmdline like "%bypass%" or object.process.cmdline like "%-w 1%")
       and object.process.parent.name in ["cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"])
| select(time, event_src.host, subject.account.name, object.process.id, object.process.parent.cmdline, object.process.cmdline)
| sort(time asc)
```
KQL:
```
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\s-e(n|nc|ncodedcommand)?\s"
| where ProcessCommandLine has_any ("-nop", "bypass", "-w 1", "hidden")
| where InitiatingProcessFileName in~ ("cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine
```

## 2. Запуск .bat/.cmd из «Загрузок» и временных папок (этап 1)

PDQL:
```
filter(msgid in ["1", "4688"] and object.process.name = "cmd.exe"
       and (object.process.cmdline like "%\\downloads\\%.bat%" or object.process.cmdline like "%\\appdata\\local\\temp\\%.bat%")
       and object.process.parent.name = "explorer.exe")
| select(time, event_src.host, subject.account.name, object.process.cmdline)
```
KQL:
```
DeviceProcessEvents
| where FileName =~ "cmd.exe" and InitiatingProcessFileName =~ "explorer.exe"
| where ProcessCommandLine matches regex @"(?i)\\(downloads|appdata\\local\\temp)\\[^""]+\.(bat|cmd)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## 3. Подключения к инфраструктуре атакующего (IoC) и PowerShell на нестандартные порты (этап 3)

PDQL:
```
filter(dst.ip = "10.158.3.4" or (msgid = "3" and event_src.title = "sysmon"
       and subject.process.name = "powershell.exe" and dst.port not in [80, 443, 3128, 8080]))
| select(time, event_src.host, subject.process.name, subject.process.id, dst.ip, dst.port)
```
KQL:
```
DeviceNetworkEvents
| where RemoteIP == "10.158.3.4"
   or (InitiatingProcessFileName =~ "powershell.exe" and RemotePort !in (80, 443, 3128, 8080))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
```
Также проверить логи прокси/МСЭ: все обращения к `10.158.3.4:9000` и URL `/download/powershell/`.

## 4. Обращение к чувствительным документам не офисными процессами (этап 5)

PDQL:
```
filter(msgid in ["4656", "4663"] and object.type = "file"
       and (object.name in ["advanced_research_report.docx", "incident_report.pdf", "expert_services_department.xls",
                            "product_fails.pdf", "product_fails_fix_plan.docx"] or object.name like "ipo_%")
       and subject.process.name not in ["explorer.exe", "winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe"])
| select(time, event_src.host, subject.account.name, subject.process.fullpath, object.fullpath, datafield5)
```
PowerShell 4103/4104 (сырые поля):
```
EventID in (4103, 4104) and (Payload or ScriptBlockText) matches "(?i)advanced_research_report|incident_report|expert_services|product_fails|\\IPO_"
```

## 5. Тот же почерк в PowerShell-логах (Module Logging 4103)

```
EventID == 4103 and ContextInfo contains "Host Application" and ContextInfo matches "(?i)-enc\s"
and Payload matches "(?i)Get-ChildItem.*(Documents|Desktop|Downloads)|is_file"
```
Структура `@{ path; name; is_file = $true }` в Payload — характерный признак файлового
браузера C2-агента, у пользователей и админов не встречается.

## Артефакты на хостах

| Артефакт | Где | Что даст |
|---|---|---|
| `launcher.bat` и его `Zone.Identifier` (ADS) | `C:\Users\*\Downloads\` | содержимое загрузчика; **URL, откуда скачан** (`HostUrl`, `ReferrerUrl`) — исходный вектор |
| История браузера, загрузки | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History` (Chrome аналогично) | когда и с какого сайта скачан файл |
| Почта пользователя | Outlook/веб-почта | было ли письмо со ссылкой или вложением (фишинг) |
| Prefetch | `C:\Windows\Prefetch\POWERSHELL.EXE-*.pf`, `CMD.EXE-*.pf`, `TIMEOUT.EXE-*.pf` | время и количество запусков |
| Amcache / ShimCache | `C:\Windows\appcompat\Programs\Amcache.hve`, реестр SYSTEM | следы `launcher.bat`, даже если он удалён |
| Закрепление | `HKCU/HKLM\...\Run`, `RunOnce`, папка «Автозагрузка», задачи планировщика (`schtasks /query /v`), службы, WMI-подписки (`root\subscription`) | остался ли агент после перезагрузки |
| Журналы PowerShell | `Microsoft-Windows-PowerShell/Operational` (4103/4104), `Windows PowerShell` (400/600) | все команды агента за пределами выгрузки |
| Память процесса | PID 4044 (если ещё жив) | дамп агента, конфиг C2 |
