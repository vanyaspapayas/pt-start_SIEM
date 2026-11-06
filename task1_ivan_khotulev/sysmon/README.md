# Sysmon

За основу взят публичный конфиг [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config).

Две правки под технику T1114.001 (см. `sysmon-config.diff`):
1. **FileCreate**: добавлено логирование создания `.zip` — виден этап упаковки
   собранной почты (`mail_dump.zip` в `%TEMP%`).
2. **ProcessCreate**: убрано исключение `powershell.exe`, чтобы не терять
   запуск скриптов сбора.

Почему Sysmon здесь помогает лишь частично: **чтение файла Sysmon не логирует**,
поэтому сам факт доступа к почте (T1114.001) детектируется только через аудит
Windows (4663). Sysmon даёт контекст: запуск процесса (EID 1), создание архива
(EID 11), родителя и командную строку.

> Полный `sysmon-config.xml` (база SwiftOnSecurity с правками выше) лежит на стенде
> в `C:\Tools\Sysmon\sysmonconfig.xml`. Приложите его в эту папку.
