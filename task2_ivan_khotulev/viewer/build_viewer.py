"""Собирает viewer/index.html из Events.jsonl (запуск: python3 build_viewer.py Events.jsonl)."""
import json, sys, pathlib

SRC = sys.argv[1] if len(sys.argv) > 1 else "Events.jsonl"
HERE = pathlib.Path(__file__).parent

# Тип события в выгрузке -> оригинальное событие Windows
ORIG = {
    "WinProcessCreate": "4688 Создание процесса",
    "SysmonProcessCreate": "Sysmon 1 Создание процесса",
    "WinHandleDuplicateAttempt": "4690 Дублирование дескриптора",
    "SysmonNetworkConnection": "Sysmon 3 Сетевое соединение",
    "WinHandleObjectRequested": "4656 Запрос дескриптора объекта",
    "WinObjectAccessAttempt": "4663 Доступ к объекту",
    "SysmonFileCreate": "Sysmon 11 Создание файла",
    "WinPowershellScriptExec": "PowerShell 4103 Выполнение конвейера",
}

def h2d(v):
    if not v: return ""
    return str(int(v, 16)) if v.lower().startswith("0x") else v

rows = []
for line in open(SRC, encoding="utf-8"):
    line = line.strip()
    if not line: continue
    w = json.loads(line); ev = json.loads(w["body"])["Event"]; s = ev["System"]
    d = {x.get("Name"): x.get("text") for x in ((ev.get("EventData") or {}).get("Data") or [])}
    t = s["EventID"]
    r = dict(time=s["TimeCreated"]["SystemTime"][:23].replace("T", " "), type=t, orig=ORIG.get(t, t),
             host=s["Computer"], rec=s["EventRecordID"], user="", pid="", ppid="", proc="",
             parent="", cmd="", obj="", net="", mask="", uuid=w.get("uuid", ""))
    if t == "WinProcessCreate":
        r.update(user=d.get("SubjectUserName"), pid=h2d(d.get("NewProcessId")), ppid=h2d(d.get("ProcessId")),
                 proc=d.get("NewProcessName"), parent=d.get("ParentProcessName"), cmd=d.get("CommandLine"))
    elif t == "SysmonProcessCreate":
        r.update(user=d.get("User"), pid=d.get("ProcessId"), ppid=d.get("ParentProcessId"), proc=d.get("Image"),
                 parent=d.get("ParentImage"), cmd=d.get("CommandLine"), obj=d.get("Hashes", "").split(",")[1] if d.get("Hashes") else "")
    elif t == "SysmonNetworkConnection":
        r.update(user=d.get("User"), pid=d.get("ProcessId"), proc=d.get("Image"),
                 net=f'{d.get("SourceIp")}:{d.get("SourcePort")} -> {d.get("DestinationIp")}:{d.get("DestinationPort")}')
    elif t in ("WinHandleObjectRequested", "WinObjectAccessAttempt"):
        r.update(user=d.get("SubjectUserName"), pid=h2d(d.get("ProcessId")), proc=d.get("ProcessName"),
                 obj=d.get("ObjectName"), mask=d.get("AccessMask"))
    elif t == "SysmonFileCreate":
        r.update(user=d.get("User"), pid=d.get("ProcessId"), proc=d.get("Image"), obj=d.get("TargetFilename"))
    elif t == "WinHandleDuplicateAttempt":
        r.update(user=d.get("SubjectUserName"), pid=h2d(d.get("SourceProcessId")),
                 obj=f'дескриптор -> PID {h2d(d.get("TargetProcessId"))}')
    elif t == "WinPowershellScriptExec":
        ctx = d.get("ContextInfo") or ""
        host_app = next((l.split("=:", 1)[1].strip() for l in ctx.splitlines() if "Host Application" in l), "")
        r.update(user=next((l.split("=:", 1)[1].strip() for l in ctx.splitlines() if l.strip().startswith("User =")), ""),
                 pid=s["Execution"]["ProcessID"], proc="powershell.exe (" + host_app[:40] + "...)",
                 cmd=(d.get("Payload") or "").strip())
        objs = [l.split('value="', 1)[1].rstrip('"') for l in (d.get("Payload") or "").splitlines() if 'name="Path"' in l]
        r["obj"] = "; ".join(objs)
    rows.append(r)

rows.sort(key=lambda r: r["time"])

# Разметка этапов атаки (по результатам расследования, см. report.html)
ATTACK_PIDS = {"9512", "4044", "6368", "12760"}
def stage(r):
    if r["type"] in ("WinProcessCreate", "SysmonProcessCreate") and r["pid"] in ("9512", "6368", "12760"):
        return "1. Запуск launcher.bat"
    if r["pid"] == "4044" and r["type"] in ("SysmonProcessCreate", "WinHandleDuplicateAttempt"):
        return "2. PowerShell-загрузчик"
    if r["type"] == "SysmonNetworkConnection" and r["time"] < "2024-11-28 13:19":
        return "3. Связь с C2"
    if r["type"] == "WinPowershellScriptExec" and "Documents\"" in r["cmd"] + '"' and "Force" in r["cmd"]:
        return "4. Разведка"
    if r["pid"] == "4044":
        return "5. Сбор и выгрузка"
    return ""
for r in rows:
    r["stage"] = stage(r)
    r["bad"] = bool(r["stage"])

tpl = (HERE / "template.html").read_text(encoding="utf-8")
(HERE / "index.html").write_text(tpl.replace("/*DATA*/[]", json.dumps(rows, ensure_ascii=False)), encoding="utf-8")
print("events:", len(rows), "attack:", sum(r["bad"] for r in rows))
