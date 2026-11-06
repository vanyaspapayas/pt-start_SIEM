# tests

Интеграционные тесты правила (формат KBT). На каждый тест пара файлов:
- `raw_events_N.json` — сырые события (отобраны по EventRecordID из нормализованных
  выгрузок со стенда, напр. sec_a + sysmon_a);
- `test_conds_N.tc` — ожидаемое число срабатываний.

| N | Сценарий                         | expect |
|---|----------------------------------|--------|
| 1 | cmd /c copy INBOX                | 5      |
| 2 | массовый сбор PowerShell         | 7      |
| 3 | легитимная работа в Thunderbird  | 0      |

Все три теста проходят (Run All, см. скриншот в README).

> Файлы `raw_events_*.json` и `test_conds_*.tc` лежат на стенде в devcontainer:
> packages/windows_open_package/correlation_rules/mitre_attck_cred_access/Local_Email_Collection_Thunderbird/tests/
> Приложите их в эту папку.
