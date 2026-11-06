# events

Сюда кладутся выгруженные со стенда журналы и сырые события SIEM.

Выгруженные `.evtx` (по два на сценарий, Security + Sysmon):

| Сценарий               | Security       | Sysmon            |
| ---------------------- | -------------- | ----------------- |
| атака `cmd /c copy`    | `sec_a.evtx`   | `sysmon_a.evtx`   |
| массовый сбор          | `sec_b.evtx`   | `sysmon_b.evtx`   |
| легитимный Thunderbird | `sec_neg.evtx` | `sysmon_neg.evtx` |

Сырые события в формате SIEM (после нормализации в vscode-xp) и собранные из них
тесты лежат в `rule/Local_Email_Collection_Thunderbird/tests/`.
