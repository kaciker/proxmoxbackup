#!/usr/bin/env python3
import hashlib, json, os, ssl, subprocess, time, urllib.parse, urllib.request
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

PVE_URL = os.getenv("PVE_URL", "https://192.168.31.5:8006/api2/json")
TOKEN_FILE = Path(os.getenv("TOKEN_FILE", "/etc/backup-dashboard/token.json"))
MANAGE_TOKEN_FILE = Path(os.getenv("MANAGE_TOKEN_FILE", "/etc/backup-dashboard/manage-token.json"))
POLICY_FILE = Path(os.getenv("POLICY_FILE", "/var/lib/backup-dashboard/policy.json"))
NODE = os.getenv("PVE_NODE", "proxmoxhx90")
PRIORITY_IDS = {100,101,102,103,104,105,107,108,109,116,117,119,120,123,127,128,129,201}
# Retention used by the current backup policy.  The destinations expected for
# each guest are taken from the configured jobs below, so pausing a job does
# not make an existing policy disappear from the dashboard.
POLICY = {"ssd-backup": 1, "usb-weekly": 1, "usb-monthly": 2, "usb-offline": 1}
STORAGES = ("ssd-backup", "usb-weekly", "usb-monthly", "usb-offline", "USB5Tb")
STATUS_CACHE = None
STATUS_CACHE_AT = 0.0
STATUS_LOCK = Lock()

def pve(path):
    token = json.loads(TOKEN_FILE.read_text())
    token_id = token.get("full-tokenid", "backup-dashboard@pve!dashboard")
    req = urllib.request.Request(f"{PVE_URL}{path}", headers={"Authorization": f"PVEAPIToken={token_id}={token['value']}"})
    with urllib.request.urlopen(req, timeout=15, context=ssl._create_unverified_context()) as response:
        return json.load(response)["data"]

def pve_manage(path, method="POST", values=None):
    token = json.loads(MANAGE_TOKEN_FILE.read_text())
    token_id = token.get("full-tokenid", "backup-dashboard@pve!manage")
    body = urllib.parse.urlencode(values or {}).encode()
    req = urllib.request.Request(f"{PVE_URL}{path}", data=body if method != "GET" else None,
        headers={"Authorization": f"PVEAPIToken={token_id}={token['value']}", "Content-Type": "application/x-www-form-urlencoded"}, method=method)
    with urllib.request.urlopen(req, timeout=20, context=ssl._create_unverified_context()) as response:
        return json.load(response).get("data")

def rule_from_job(job):
    prune = job.get("prune-backups", {}) or {}
    return {"storage": job.get("storage", ""), "schedule": job.get("schedule", ""), "mode": job.get("mode", "snapshot"),
            "keep_last": int(prune.get("keep-last", 0) or 0), "enabled": bool(job.get("enabled", 1)),
            "comment": job.get("comment", ""), "notes_template": job.get("notes-template", "")}

def live_policy(guests, jobs):
    rules = defaultdict(list)
    for job in jobs:
        rule = rule_from_job(job)
        for value in str(job.get("vmid", "")).split(","):
            if value.isdigit(): rules[int(value)].append(rule.copy())
    saved = {}
    if POLICY_FILE.exists():
        try: saved = json.loads(POLICY_FILE.read_text())
        except Exception: saved = {}
    result = {"version": 1, "guests": {}}
    for vmid, guest in guests.items():
        old = saved.get("guests", {}).get(str(vmid), {})
        result["guests"][str(vmid)] = {
            "priority": bool(old["priority"]) if "priority" in old else (guest["status"] == "running" or vmid in PRIORITY_IDS),
            "rules": old.get("rules", rules.get(vmid, [])),
        }
    return result

def exported_archives():
    cmd = ["/usr/bin/ssh", "-i", "/etc/backup-dashboard/id_ed25519", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/etc/backup-dashboard/known_hosts", "-o", "ConnectTimeout=10", "backup-dashboard@192.168.31.5"]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=20)
    return json.loads(result.stdout)

def group_archives(archives):
    grouped = defaultdict(list)
    for storage, rows in archives.items():
        for row in rows:
            vmid = str(row.get("vmid", ""))
            if vmid: grouped[(vmid, storage)].append(row)
    for rows in grouped.values(): rows.sort(key=lambda row: row.get("ctime", 0), reverse=True)
    return grouped

def total(rows): return sum(int(row.get("size", 0) or 0) for row in rows)

def snapshot_data(guests):
    """Read-only snapshot inventory; Proxmox also returns a synthetic 'current' row."""
    def read_guest(item):
        vmid, guest = item
        try:
            rows = pve(f"/nodes/{NODE}/{guest['type']}/{vmid}/snapshot") or []
            real = [row for row in rows if row.get("name") != "current"]
            real.sort(key=lambda row: row.get("snaptime", 0) or 0, reverse=True)
            return vmid, {"count": len(real), "latest": real[0].get("snaptime", 0) if real else 0}
        except Exception as error:
            return vmid, {"error": str(error)}

    result = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(read_guest, item) for item in guests.items()]
        for future in as_completed(futures):
            vmid, value = future.result()
            result[vmid] = value
    return result

def backup_data():
    resources = pve("/cluster/resources?type=vm")
    jobs = pve("/cluster/backup")
    storages = pve(f"/nodes/{NODE}/storage")
    archives = exported_archives()
    grouped = group_archives(archives)
    guests = {}
    for item in resources:
        if item.get("node") == NODE and item.get("type") in ("qemu", "lxc"):
            vmid = int(item["vmid"])
            guests[vmid] = {"id": vmid, "name": item.get("name", ""), "type": item["type"], "status": item.get("status", "unknown"), "disk": item.get("maxdisk", 0)}
    snapshots = snapshot_data(guests)
    policy = live_policy(guests, jobs)
    job_map = defaultdict(list)
    for job in jobs:
        for value in str(job.get("vmid", "")).split(","):
            if value:
                storage = job.get("storage")
                prune = job.get("prune-backups", {})
                job_map[int(value)].append({"storage": storage, "schedule": job.get("schedule"), "mode": job.get("mode"), "prune": prune, "enabled": bool(job.get("enabled", 1))})
    retention_by_storage = defaultdict(int)
    for item in policy["guests"].values():
        for rule in item.get("rules", []):
            if rule.get("enabled", True) and rule.get("storage") in STORAGES:
                retention_by_storage[rule["storage"]] = max(retention_by_storage[rule["storage"]], int(rule.get("keep_last", 0) or 0))
    views = {}
    for vmid, guest in guests.items():
        priority = bool(policy["guests"].get(str(vmid), {}).get("priority", False))
        # The backup jobs are the source of truth for the policy.  This keeps
        # the dashboard aligned with Proxmox even while jobs are paused.
        expected = sorted({rule.get("storage") for rule in policy["guests"].get(str(vmid), {}).get("rules", []) if rule.get("enabled", True) and rule.get("storage") in STORAGES}, key=STORAGES.index)
        copies = []
        for storage in STORAGES:
            rows = grouped.get((str(vmid), storage), [])
            if rows: copies.append({"storage": storage, "count": len(rows), "size": total(rows), "latest": rows[0].get("ctime", 0), "latest_size": rows[0].get("size", 0), "format": rows[0].get("format", "")})
        views[vmid] = {**guest, "priority": priority, "expected": expected, "desired_rules": policy["guests"].get(str(vmid), {}).get("rules", []), "copies": copies, "jobs": job_map.get(vmid, []), "snapshots": snapshots.get(vmid, {"error": "sin datos"})}
    garbage = defaultdict(lambda: {"count": 0, "size": 0, "latest": 0, "files": []})
    for (vmid_text, storage), rows in grouped.items():
        vmid = int(vmid_text)
        if storage == "USB5Tb": reason, candidates = "fuera de la política actual (USB5Tb)", rows
        elif vmid not in guests: reason, candidates = "invitado inexistente actualmente", rows
        else:
            keep = retention_by_storage.get(storage, POLICY.get(storage, 0))
            reason, candidates = "copias antiguas fuera de retención", rows[keep:] if keep else rows
        if candidates:
            key = (vmid_text, storage, reason); entry = garbage[key]
            entry["count"] += len(candidates); entry["size"] += total(candidates); entry["latest"] = max(row.get("ctime", 0) for row in candidates); entry["files"] = [row.get("volid", "") for row in candidates[:5]]
    archive_usage = {storage: total(rows) for storage, rows in archives.items()}
    archive_counts = {storage: len(rows) for storage, rows in archives.items()}
    storage_view = [{"name": row.get("storage"), "total": row.get("total", 0), "used": row.get("used", 0), "avail": row.get("avail", 0), "backup_size": archive_usage.get(row.get("storage"), 0), "backup_count": archive_counts.get(row.get("storage"), 0), "shared_disk": row.get("storage") != "ssd-backup"} for row in storages if row.get("storage") in STORAGES]
    priority_views = (row for row in views.values() if row["priority"])
    other_views = (row for row in views.values() if not row["priority"])
    return {"updated": int(time.time()), "priority": sorted(priority_views, key=lambda row: row["id"]), "other": sorted(other_views, key=lambda row: row["id"]), "garbage": [{"vmid": int(vmid), "storage": storage, "reason": reason, **value} for (vmid, storage, reason), value in sorted(garbage.items())], "storages": storage_view, "policy": policy}

MANAGED_LEGACY_IDS = {"critical-weekly-ssd", "critical-monthly-usb", "noncritical-weekly-usb", "noncritical-monthly-offline"}

def save_policy(policy):
    POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = POLICY_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(policy, ensure_ascii=False, indent=2) + "\n")
    os.replace(temporary, POLICY_FILE)

def sync_policy(policy, apply=True):
    jobs = pve("/cluster/backup")
    existing = {job.get("id"): job for job in jobs if job.get("id")}
    groups = defaultdict(list)
    for vmid, item in policy.get("guests", {}).items():
        for rule in item.get("rules", []):
            storage = rule.get("storage")
            if storage not in STORAGES or storage == "USB5Tb": continue
            key = (storage, rule.get("schedule", ""), rule.get("mode", "snapshot"), int(rule.get("keep_last", 0) or 0),
                   bool(rule.get("enabled", True)), rule.get("comment", ""), rule.get("notes_template", ""))
            groups[key].append(int(vmid))
    desired = {}
    for key, vmids in groups.items():
        storage, schedule, mode, keep_last, enabled, comment, notes_template = key
        digest = hashlib.sha1(json.dumps(key, ensure_ascii=False).encode()).hexdigest()[:10]
        job_id = "dashboard-" + storage.replace("_", "-") + "-" + digest
        desired[job_id] = {"id": job_id, "vmid": ",".join(map(str, sorted(set(vmids)))), "storage": storage,
                           "schedule": schedule, "mode": mode, "compress": "zstd", "enabled": 1 if enabled else 0,
                           "prune-backups": f"keep-last={keep_last}" if keep_last else "", "comment": comment,
                           "notes-template": notes_template}
    changes = []
    for job_id, values in desired.items(): changes.append({"action": "update" if job_id in existing else "create", "id": job_id, "vmid": values["vmid"], "storage": values["storage"]})
    stale = [job_id for job_id in existing if job_id in MANAGED_LEGACY_IDS or job_id.startswith("dashboard-") and job_id not in desired]
    changes.extend({"action": "delete", "id": job_id} for job_id in stale)
    if apply:
        for job_id, values in desired.items():
            payload = {k: v for k, v in values.items() if k != "id" and v != ""}
            if job_id in existing: pve_manage(f"/cluster/backup/{urllib.parse.quote(job_id, safe='')}", "PUT", payload)
            else: pve_manage("/cluster/backup", "POST", {**payload, "id": job_id})
        for job_id in stale: pve_manage(f"/cluster/backup/{urllib.parse.quote(job_id, safe='')}", "DELETE")
    return changes

def manual_backup(vmid, storage):
    resources = pve("/cluster/resources?type=vm")
    guest = next((item for item in resources if int(item.get("vmid", -1)) == vmid and item.get("node") == NODE and item.get("type") in ("qemu", "lxc")), None)
    if not guest: raise ValueError("VM/CT no encontrado en el nodo configurado")
    policy = json.loads(POLICY_FILE.read_text()) if POLICY_FILE.exists() else {"guests": {}}
    rules = [rule for rule in policy.get("guests", {}).get(str(vmid), {}).get("rules", []) if rule.get("enabled", True) and rule.get("storage") == storage]
    if not rules: raise ValueError("El destino no está definido en la política del panel")
    rule = rules[0]
    values = {"storage": storage, "mode": rule.get("mode", "snapshot"), "compress": "zstd"}
    if rule.get("notes_template"): values["notes-template"] = rule["notes_template"]
    task = pve_manage(f"/nodes/{NODE}/{guest['type']}/{vmid}/vzdump", "POST", values)
    return {"upid": task, "vmid": vmid, "storage": storage}

HTML = r'''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#09111f"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"><meta name="apple-mobile-web-app-title" content="Backups Proxmox"><link rel="manifest" href="/manifest.webmanifest"><link rel="icon" href="/icon.svg" type="image/svg+xml"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><title>Proxmox · Control de copias</title><style>
:root{color-scheme:dark;--bg:#09111f;--panel:#111c2e;--line:#24344d;--text:#edf4ff;--muted:#9eafc8;--ok:#38d996;--bad:#fb7185;--warn:#fbbf24;--blue:#60a5fa}*{box-sizing:border-box}body{margin:0;font:14px system-ui,sans-serif;background:linear-gradient(130deg,#0b1325,#09111f);color:var(--text)}main{max-width:1600px;margin:auto;padding:28px}h1{margin:0;font-size:28px}h2{margin:28px 0 10px;font-size:19px}.sub{color:var(--muted);margin:6px 0 0}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-top:20px}.card,.notice{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}.metric{font-size:21px;font-weight:700;margin-top:7px}.bar{height:6px;background:#202f45;border-radius:5px;margin-top:10px;overflow:hidden}.bar i{display:block;height:100%;background:var(--blue)}table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:11px;letter-spacing:.04em;color:var(--muted);background:#0e192a}tr:last-child td{border:0}.pill,.copy,.snapshot{display:inline-block;border-radius:99px;font-size:12px;font-weight:700}.pill{padding:3px 7px}.on{color:#082419;background:var(--ok)}.off{color:#351017;background:var(--bad)}.good{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.copy{padding:3px 6px;margin:2px 2px 2px 0;background:#203450;font-weight:400;white-space:nowrap}.copy.missing{background:#4a1f2c;color:#ffb4c0}.copy.extra{background:#493a17;color:#ffe49b}.snapshot{padding:4px 7px;background:#102b25;color:var(--ok);white-space:nowrap}.snapshot.has{background:#493a17;color:#ffe49b}.snapshot.error{background:#4a1f2c;color:#ffb4c0}.small{font-size:12px;color:var(--muted)}.empty{color:var(--ok);padding:14px;background:#102b25;border-radius:10px}@media(max-width:900px){main{padding:16px}table{font-size:12px}th,td{padding:7px 5px}.hide{display:none}}
</style></head><body><main><h1>Proxmox · Control de copias</h1><p class="sub" id="updated">Cargando datos actuales…</p><section class="cards" id="storage"></section><h2>Prioritarios: copias y espacio</h2><p class="sub">Incluye los invitados encendidos y los invitados críticos definidos en la política.</p><div id="priority"></div><h2>Basura / fuera de política</h2><p class="sub">Backups de invitados inexistentes, almacenes heredados o copias que exceden la retención configurada.</p><div id="garbage"></div><h2>Resto de invitados</h2><div id="other"></div></main><script>
const f=new Intl.DateTimeFormat('es-ES',{dateStyle:'medium',timeStyle:'short'});const b=n=>{if(!n)return'0 B';let u=['B','KiB','MiB','GiB','TiB'],i=0;while(n>=1024&&i<4){n/=1024;i++}return n.toFixed(1)+' '+u[i]};const date=n=>n?f.format(n*1000):'—';
function copyCell(row){const by=Object.fromEntries(row.copies.map(c=>[c.storage,c]));return row.expected.map(s=>{const c=by[s];return c?`<span class="copy">${s}: ${c.count} · ${b(c.size)}</span>`:`<span class="copy missing">${s}: FALTA</span>`}).join('')+(by.USB5Tb?`<span class="copy extra">USB5Tb: ${by.USB5Tb.count} · ${b(by.USB5Tb.size)}</span>`:'')}
function snapshotCell(x){const s=x.snapshots||{};if(s.error)return'<span class="snapshot error">ERROR</span><br><span class="small">No disponible</span>';if(!s.count)return'<span class="snapshot">0 · ninguno</span>';return`<span class="snapshot has">${s.count} · último ${date(s.latest)}</span>`}
function row(x){const found=x.expected.filter(s=>x.copies.some(c=>c.storage===s)).length;const ok=found===x.expected.length;return `<tr><td>${x.id}</td><td><strong>${x.name}</strong><br><span class="small">${x.type.toUpperCase()} · ${x.status}</span></td><td>${ok?'<span class="good">OK</span>':'<span class="bad">INCOMPLETO</span>'}<br><span class="small">${found}/${x.expected.length} destinos</span></td><td>${copyCell(x)}</td><td>${snapshotCell(x)}</td><td>${x.jobs.length?x.jobs.map(j=>`<span class="copy ${j.enabled?'':'extra'}">${j.storage} · ${j.schedule||'manual'}${j.enabled?'':' · DESACTIVADO'}</span>`).join(''):'<span class="small">Sin trabajo</span>'}</td></tr>`}
function table(rows){if(!rows.length)return'<div class="empty">No hay elementos.</div>';return`<table><thead><tr><th>ID</th><th>Invitado</th><th>Estado copia</th><th>Copias existentes · espacio total</th><th>Snapshots</th><th>Programación</th></tr></thead><tbody>${rows.map(row).join('')}</tbody></table>`}
function garbage(rows){if(!rows.length)return'<div class="empty">No se ha detectado basura.</div>';return`<table><thead><tr><th>ID</th><th>Almacén</th><th>Motivo</th><th>Archivos</th><th>Espacio</th><th>Último</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${x.vmid}</td><td>${x.storage}</td><td class="warn">${x.reason}</td><td>${x.count}</td><td>${b(x.size)}</td><td>${date(x.latest)}<br><span class="small">${x.files.filter(Boolean).join('<br>')}</span></td></tr>`).join('')}</tbody></table>`}
async function load(){try{const d=await fetch('/api/status').then(r=>r.json());document.querySelector('#updated').textContent='Actualizado '+date(d.updated)+' · recarga automática cada 5 min';document.querySelector('#storage').innerHTML=d.storages.map(s=>{const p=s.total?100*s.used/s.total:0;return s.shared_disk?`<article class="card"><strong>${s.name}</strong><div class="metric">${b(s.backup_size)} en backups</div><div class="sub">Disco USB compartido: ${b(s.used)} usados · ${b(s.avail)} libres</div><div class="bar"><i style="width:${p}%"></i></div></article>`:`<article class="card"><strong>${s.name}</strong><div class="metric">${b(s.avail)} libres</div><div class="sub">${b(s.used)} usados de ${b(s.total)} · backups: ${b(s.backup_size)}</div><div class="bar"><i style="width:${p}%"></i></div></article>`}).join('');document.querySelector('#priority').innerHTML=table(d.priority);document.querySelector('#garbage').innerHTML=garbage(d.garbage);document.querySelector('#other').innerHTML=table(d.other)}catch(e){document.querySelector('#updated').textContent='Error al consultar datos actuales: '+e.message}}load();setInterval(load,300000);
</script></body></html>'''

HTML = HTML.replace('<section class="cards" id="storage"></section>', '<div id="storage"></div>')
HTML = HTML.replace('load();setInterval(load,300000);', '')
HTML = HTML.replace('</style>', '''
.storage-section{margin-top:20px;padding:16px;border-radius:14px;border:1px solid var(--line)}.storage-section h2{margin:0 0 4px}.ssd-section{background:#0d1e35;border-color:#32649e}.usb-section{background:#211b2c;border-color:#7555a2}.storage-label{font-size:12px;color:var(--muted)}.physical-card{border-color:#5799e6;background:#102a48}.policy-weekly{border-color:#3b82f6}.policy-monthly{border-color:#a78bfa}.policy-offline{border-color:#f59e0b}.policy-legacy{border-color:#fb7185}.policy-ssd{border-color:#60a5fa}.physical-overview{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:20px}.physical-overview-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}.physical-overview-card.ssd{border-color:#5799e6}.physical-overview-card.usb{border-color:#a78bfa}.physical-title{font-size:18px;font-weight:700}.physical-metric{font-size:25px;font-weight:700;margin-top:10px}.physical-sub{color:var(--muted);margin-top:5px}.policy-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}.policy-badge{padding:6px 9px;border-radius:8px;font-size:12px}.policy-badge.weekly{background:#183a71;border:1px solid #3b82f6}.policy-badge.monthly{background:#30245a;border:1px solid #a78bfa}.policy-badge.offline{background:#4a3511;border:1px solid #f59e0b}.policy-badge.legacy{background:#4a202e;border:1px solid #fb7185}.physical-bar{height:8px;background:#202f45;border-radius:5px;margin-top:14px;overflow:hidden}.physical-bar i{display:block;height:100%;background:#60a5fa}@media(max-width:900px){.physical-overview{grid-template-columns:1fr}}
</style>''', 1)
HTML = HTML.replace('</body></html>', r'''<script>
let loading=false;
async function loadDashboard(){
  if(loading)return; loading=true;
  try{
    const response=await fetch('/api/status',{cache:'no-store'});
    if(!response.ok)throw new Error('HTTP '+response.status);
    const d=await response.json();
    const ssd=d.storages.find(x=>!x.shared_disk), usb=d.storages.find(x=>x.shared_disk), policies=d.storages.filter(x=>x.shared_disk);
    const cls={'usb-weekly':'policy-weekly','usb-monthly':'policy-monthly','usb-offline':'policy-offline','USB5Tb':'policy-legacy'};
    const labels={'usb-weekly':'Copias semanales','usb-monthly':'Copias mensuales','usb-offline':'Copias offline','USB5Tb':'Almacén heredado / general'};
    const physical=n=>{if(!n)return'0 B';let u=['B','KiB','MiB','GiB','TiB'],i=0;while(n>=1024&&i<4){n/=1024;i++}return n.toFixed(1)+' '+u[i]};
    let h='<div class="physical-overview">';
    if(ssd){const p=ssd.total?100*ssd.used/ssd.total:0;h+=`<section class="storage-section ssd-section"><h2>Disco SSD independiente</h2><div class="storage-label">Capacidad física exclusiva de ssd-backup.</div><div class="cards"><article class="card physical-card"><strong>ssd-backup</strong><div class="metric">${physical(ssd.avail)} libres</div><div class="sub">${physical(ssd.used)} usados de ${physical(ssd.total)} · backups: ${physical(ssd.backup_size)} (${ssd.backup_count} archivos)</div><div class="bar"><i style="width:${p}%"></i></div></article></div></section>`}
    if(usb){const p=usb.total?100*usb.used/usb.total:0;h+=`<section class="storage-section usb-section"><h2>Disco USB físico compartido</h2><div class="storage-label">Una sola capacidad física: ${physical(usb.used)} usados · ${physical(usb.avail)} libres de ${physical(usb.total)}.</div><div class="cards"><article class="card physical-card"><strong>Disco USB común</strong><div class="metric">${physical(usb.avail)} libres</div><div class="sub">Ocupación física total del USB</div><div class="bar"><i style="width:${p}%"></i></div></article>${policies.map(s=>`<article class="card ${cls[s.name]||''}"><strong>${labels[s.name]||s.name}</strong><div class="metric">${physical(s.backup_size)} en backups</div><div class="sub">Almacén lógico: <b>${s.name}</b><br>${s.backup_count} archivos · no es capacidad física adicional.</div></article>`).join('')}</div></section>`}
    h+='</div>'; document.querySelector('#storage').innerHTML=h;
    document.querySelector('#updated').textContent='Actualizado '+date(d.updated)+' · recarga automática cada 5 min';
    document.querySelector('#priority').innerHTML=table(d.priority); document.querySelector('#garbage').innerHTML=garbage(d.garbage); document.querySelector('#other').innerHTML=table(d.other);
  }catch(e){document.querySelector('#updated').textContent='Error al consultar datos actuales: '+e.message+' · reintentando en 5 min'}finally{loading=false}
}
loadDashboard(); setInterval(loadDashboard,300000);
</script></body></html>''', 1)

HTML = HTML.replace('</style>', '''.tabs{display:flex;gap:8px;margin:18px 0}.tab{border:1px solid var(--line);background:#14243a;color:var(--text);padding:9px 14px;border-radius:9px;cursor:pointer}.tab.active{background:var(--blue);color:#071321}.inventory-tools{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}.button{border:0;border-radius:9px;padding:10px 14px;background:var(--blue);color:#071321;font-weight:700;cursor:pointer}.button.secondary{background:#263b58;color:var(--text)}.button.warn{background:#fbbf24;color:#241b00}.inventory-scroll{overflow:auto}.inventory-table{min-width:1120px}.rule{display:grid;grid-template-columns:125px 125px 52px 1fr 26px;gap:5px;margin:4px 0}.rule input,.rule select{min-width:0;background:#0b1728;border:1px solid var(--line);color:var(--text);border-radius:5px;padding:5px;font:inherit}.rule input[type=number]{width:52px}.rule-delete{color:var(--bad);cursor:pointer;background:none;border:0;font-size:18px}.priority-toggle{accent-color:var(--ok);transform:scale(1.2)}.sync-result{white-space:pre-wrap;background:#0b1728;border:1px solid var(--line);border-radius:9px;padding:12px;margin-top:12px}.inventory-note{color:var(--muted);font-size:13px}@media(max-width:900px){.tabs{position:sticky;top:0;background:var(--bg);padding:8px 0;z-index:2}}</style>''', 1)
HTML = HTML.replace("""<body><main><h1>Proxmox · Control de copias</h1>""", """<body><main><h1>Proxmox · Control de copias</h1><nav class="tabs"><button class="tab active" id="tab-dashboard" onclick="showTab('dashboard')">Estado</button><button class="tab" id="tab-inventory" onclick="showTab('inventory')">Inventario y políticas</button></nav>""")
HTML = HTML.replace('<div id="storage"></div><h2>Prioritarios:', '<div id="dashboard-view"><div id="storage"></div><h2>Prioritarios:')
HTML = HTML.replace('<div id="other"></div></main>', '<div id="other"></div></div><section id="inventory-view" style="display:none"><h2>Inventario y políticas</h2><p class="inventory-note">Aquí defines la intención del sistema. Guardar conserva los cambios en el dashboard; sincronizar modifica únicamente los trabajos gestionados por esta web en Proxmox. No crea ni borra backups existentes.</p><div class="inventory-tools"><button class="button secondary" onclick="savePolicy()">Guardar reglas</button><button class="button warn" onclick="saveAndSync()">Guardar + sincronizar</button><button class="button" onclick="previewPolicy()">Validar cambios</button><button class="button warn" id="apply-sync" style="display:none" onclick="applySync()">Aplicar sincronización</button></div><div id="sync-result"></div><div class="inventory-scroll"><div id="inventory"></div></div></section></main>')
HTML = HTML.replace('</style>', '.sync-overlay{position:fixed;inset:0;background:rgba(3,8,18,.62);display:none;align-items:center;justify-content:center;z-index:20}.sync-box{min-width:250px;text-align:center;background:var(--panel);border:1px solid var(--blue);border-radius:14px;padding:22px;box-shadow:0 12px 40px #0008}.sync-spinner{width:28px;height:28px;margin:0 auto 12px;border:3px solid #29415e;border-top-color:var(--blue);border-radius:50%;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.sync-box strong{display:block}.sync-box span{display:block;color:var(--muted);font-size:12px;margin-top:6px}.button:disabled{opacity:.45;cursor:wait}</style>', 1)
HTML = HTML.replace('</section></main>', '<div id="sync-overlay" class="sync-overlay"><div class="sync-box"><div class="sync-spinner"></div><strong>Sincronizando con Proxmox…</strong><span>Aplicando la política y verificando el estado</span></div></div></section></main>')
HTML = HTML.replace('</body></html>', r'''<script>var inventoryData=null,dPriority=[],dOther=[];function showTab(name){var dash=name==='dashboard';document.getElementById('dashboard-view').style.display=dash?'block':'none';document.getElementById('inventory-view').style.display=dash?'none':'block';document.getElementById('tab-dashboard').classList.toggle('active',dash);document.getElementById('tab-inventory').classList.toggle('active',!dash);if(!dash)loadInventory()}function esc(v){return String(v||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;')}function ruleHtml(r){r=r||{};return '<div class=\"rule\"><select data-field=\"storage\"><option value=\"ssd-backup\" '+(r.storage==='ssd-backup'?'selected':'')+'>ssd-backup</option><option value=\"usb-weekly\" '+(r.storage==='usb-weekly'?'selected':'')+'>usb-weekly</option><option value=\"usb-monthly\" '+(r.storage==='usb-monthly'?'selected':'')+'>usb-monthly</option><option value=\"usb-offline\" '+(r.storage==='usb-offline'?'selected':'')+'>usb-offline</option></select><input data-field=\"schedule\" value=\"'+esc(r.schedule)+'\" placeholder=\"sun 03:00\"><input data-field=\"keep_last\" type=\"number\" min=\"0\" value=\"'+(r.keep_last||0)+'\" title=\"Copias a conservar\"><input data-field=\"comment\" value=\"'+esc(r.comment)+'\" placeholder=\"Comentario\"><button class=\"rule-delete\" onclick=\"this.parentElement.remove()\">×</button></div>'}function renderInventory(){var rows=dPriority.concat(dOther),html='<table class=\"inventory-table\"><thead><tr><th>ID</th><th>Invitado</th><th>Prioritario</th><th>Reglas · destino / frecuencia / copias / comentario</th><th>Estado actual</th></tr></thead><tbody>';rows.forEach(function(x){var p=inventoryData.guests[String(x.id)]||{priority:x.priority,rules:[]};html+='<tr data-vmid=\"'+x.id+'\"><td>'+x.id+'</td><td><strong>'+esc(x.name)+'</strong><br><span class=\"small\">'+x.type.toUpperCase()+' · '+x.status+'</span></td><td><input class=\"priority-toggle\" type=\"checkbox\" '+(p.priority?'checked':'')+'></td><td><div class=\"rules\">'+(p.rules||[]).map(ruleHtml).join('')+'</div><button class=\"button secondary\" onclick=\"addRule(this)\">+ regla</button></td><td>'+((x.expected||[]).join(', ')||'Sin política')+'</td></tr>'});document.getElementById('inventory').innerHTML=html+'</tbody></table>'}function addRule(b){b.previousElementSibling.insertAdjacentHTML('beforeend',ruleHtml({storage:'ssd-backup',schedule:'sun 01:00',keep_last:1,comment:''}))}function collectPolicy(){var guests={};document.querySelectorAll('#inventory tbody tr').forEach(function(row){var rules=[];row.querySelectorAll('.rule').forEach(function(r){var o={mode:'snapshot',enabled:true,notes_template:''};r.querySelectorAll('[data-field]').forEach(function(i){o[i.dataset.field]=i.type==='number'?Number(i.value||0):i.value});rules.push(o)});guests[row.dataset.vmid]={priority:row.querySelector('.priority-toggle').checked,rules:rules}});return{version:1,guests:guests}}async function loadInventory(){try{var d=await fetch('/api/status?inventory='+Date.now()).then(function(r){return r.json()});inventoryData=d.policy||{version:1,guests:{}};dPriority=d.priority;dOther=d.other;renderInventory()}catch(e){document.getElementById('inventory').innerHTML='<div class=\"empty\">No se pudo cargar el inventario: '+esc(e.message)+'</div>'}}async function savePolicy(){var r=await fetch('/api/policy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(collectPolicy())}).then(function(x){return x.json()});document.getElementById('sync-result').textContent=r.ok?'Reglas guardadas localmente.':'Error: '+r.error;document.getElementById('apply-sync').style.display='none'}async function previewPolicy(){await savePolicy();var r=await fetch('/api/preview',{method:'POST'}).then(function(x){return x.json()});if(!r.ok){document.getElementById('sync-result').textContent='Error: '+r.error;return}document.getElementById('sync-result').textContent=r.changes.length?r.changes.map(function(x){return x.action.toUpperCase()+' '+x.id+(x.vmid?' → '+x.vmid:'')}).join('\\n'):'No hay cambios de trabajos que aplicar';document.getElementById('apply-sync').style.display=r.changes.length?'inline-block':'none'}async function applySync(){if(!confirm('Se modificarán los trabajos de backup gestionados por esta web en Proxmox. ¿Continuar?'))return;var r=await fetch('/api/sync',{method:'POST'}).then(function(x){return x.json()});document.getElementById('sync-result').textContent=r.ok?'Sincronización aplicada:\\n'+(r.changes.map(function(x){return x.action.toUpperCase()+' '+x.id}).join('\\n')||'sin cambios'):'Error: '+r.error;document.getElementById('apply-sync').style.display='none'}</script></body></html>''', 1)
HTML = HTML.replace('</body></html>', r'''<script>var PROFILE_RULES={priority:[{storage:'ssd-backup',schedule:'sun 01:00',keep_last:1,comment:'CRITICOS | semanal SSD | domingo 01:00 | conservar 1 copia'},{storage:'usb-monthly',schedule:'*-*-01 04:00',keep_last:2,comment:'CRITICOS | mensual USB | día 1 a las 04:00 | conservar 2 copias'}],nonpriority:[{storage:'usb-weekly',schedule:'sun 03:00',keep_last:1,comment:'NO CRITICOS | semanal USB | domingo 03:00 | conservar 1 copia'},{storage:'usb-offline',schedule:'*-*-01 05:30',keep_last:1,comment:'NO CRITICOS | mensual USB offline | día 1 a las 05:30 | conservar 1 copia'}]};function profileChanged(box){var rules=box.closest('tr').querySelector('.rules');rules.innerHTML=(box.checked?PROFILE_RULES.priority:PROFILE_RULES.nonpriority).map(ruleHtml).join('');document.getElementById('sync-result').textContent='Perfil cambiado: reglas por defecto cargadas. Pulsa Guardar + sincronizar para aplicarlo.'}document.addEventListener('change',function(e){if(e.target.classList&&e.target.classList.contains('priority-toggle'))profileChanged(e.target)});async function saveAndSync(){var saved=await fetch('/api/policy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(collectPolicy())}).then(function(x){return x.json()});if(!saved.ok){document.getElementById('sync-result').textContent='Error guardando: '+saved.error;return}if(!confirm('Se modificarán los trabajos de backup gestionados por esta web en Proxmox. ¿Continuar?'))return;var r=await fetch('/api/sync',{method:'POST'}).then(function(x){return x.json()});document.getElementById('sync-result').textContent=r.ok?'Sincronización aplicada. Recargando estado real de Proxmox…':'Error sincronizando: '+r.error;if(r.ok){document.getElementById('apply-sync').style.display='none';await loadDashboard();showTab('dashboard')}}applySync=saveAndSync;</script></body></html>''', 1)
HTML = HTML.replace('</body></html>', r'''<script>var syncBusy=false,rawSaveAndSync=saveAndSync;saveAndSync=async function(){if(syncBusy)return;syncBusy=true;var started=Date.now(),overlay=document.getElementById('sync-overlay'),buttons=document.querySelectorAll('#inventory-view .button');overlay.style.display='flex';buttons.forEach(function(b){b.disabled=true});try{await rawSaveAndSync()}finally{setTimeout(function(){overlay.style.display='none';buttons.forEach(function(b){b.disabled=false});syncBusy=false},Math.max(0,2000-(Date.now()-started)))}};applySync=saveAndSync;</script></body></html>''', 1)
HTML = HTML.replace('</style>', '.schedule-menu{position:relative;display:inline-block}.schedule-menu summary{list-style:none;cursor:pointer}.schedule-menu summary::-webkit-details-marker{display:none}.schedule-status{display:inline-block;border-radius:99px;padding:4px 8px;font-size:12px;font-weight:700;white-space:nowrap}.schedule-good{background:#102b25;color:var(--ok)}.schedule-bad{background:#4a1f2c;color:#ffb4c0}.schedule-popup{position:absolute;right:0;top:30px;z-index:10;min-width:320px;padding:8px;background:var(--panel);border:1px solid var(--line);border-radius:10px;box-shadow:0 10px 30px #0008}.schedule-line{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:4px 0}.manual-button{border:0;border-radius:7px;background:var(--blue);color:#071321;font-weight:700;cursor:pointer;padding:4px 8px}.manual-button:disabled{opacity:.45;cursor:wait}</style>', 1)
HTML = HTML.replace('</main><script>', '<div id="manual-overlay" class="sync-overlay"><div class="sync-box"><div class="sync-spinner"></div><strong>Lanzando backup…</strong><span>Proxmox está iniciando la copia manual</span></div></div></main><script>', 1)
HTML = HTML.replace('</body></html>', r'''<script>function scheduleCell(x){var by=Object.fromEntries(x.copies.map(function(c){return[c.storage,c]})),rules=(x.desired_rules||[]).filter(function(r){return r.enabled!==false}),complete=rules.length>0&&rules.every(function(r){return by[r.storage]});if(!rules.length)return'<span class="small">Sin programación</span>';var lines=rules.map(function(r){return'<div class="schedule-line"><span class="schedule-status '+(by[r.storage]?'schedule-good':'schedule-bad')+'">'+r.storage+' · '+(r.schedule||'manual')+' · '+(by[r.storage]?'OK':'FALTA')+'</span><button class="manual-button" onclick="manualBackup('+x.id+',\\''+r.storage+'\\')">▶</button></div>'}).join('');return'<details class="schedule-menu"><summary><span class="schedule-status '+(complete?'schedule-good':'schedule-bad')+'">'+(complete?'OK':'INCOMPLETO')+' · '+rules.length+' reglas</span></summary><div class="schedule-popup">'+lines+'</div></details>'}function row(x){var found=x.expected.filter(function(s){return x.copies.some(function(c){return c.storage===s})}).length,ok=found===x.expected.length;return'<tr><td>'+x.id+'</td><td><strong>'+x.name+'</strong><br><span class="small">'+x.type.toUpperCase()+' · '+x.status+'</span></td><td>'+(ok?'<span class="good">OK</span>':'<span class="bad">INCOMPLETO</span>')+'<br><span class="small">'+found+'/'+x.expected.length+' destinos</span></td><td>'+copyCell(x)+'</td><td>'+snapshotCell(x)+'</td><td>'+scheduleCell(x)+'</td></tr>'}var manualBusy=false;async function manualBackup(vmid,storage){if(manualBusy)return;if(!confirm('Lanzar ahora el backup de la máquina '+vmid+' hacia '+storage+'?'))return;manualBusy=true;var overlay=document.getElementById('manual-overlay'),started=Date.now();overlay.style.display='flex';document.querySelectorAll('.manual-button').forEach(function(b){b.disabled=true});try{var r=await fetch('/api/manual-backup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vmid:vmid,storage:storage})}).then(function(x){return x.json()});document.getElementById('updated').textContent=r.ok?'Backup manual lanzado para '+vmid+' → '+storage+(r.task&&r.task.upid?' · tarea iniciada':''):'Error al lanzar backup: '+r.error;if(r.ok)setTimeout(loadDashboard,1500)}finally{setTimeout(function(){overlay.style.display='none';document.querySelectorAll('.manual-button').forEach(function(b){b.disabled=false});manualBusy=false},Math.max(0,2000-(Date.now()-started)))}}</script></body></html>''', 1)

# La tabla se carga desde el primer script de la página. Sustituimos también
# la función original para que no haya una carrera entre el primer fetch y los
# scripts de mejoras añadidos después del HTML base.
old_row = HTML[HTML.index('function row(x){'):HTML.index('function table(rows)')]
new_row = r'''function scheduleCell(x){var by=Object.fromEntries(x.copies.map(function(c){return[c.storage,c]})),rules=(x.desired_rules||[]).filter(function(r){return r.enabled!==false}),complete=rules.length>0&&rules.every(function(r){return by[r.storage]});if(!rules.length)return'<span class="small">Sin programación</span>';var lines=rules.map(function(r){return'<div class="schedule-line"><span class="schedule-status '+(by[r.storage]?'schedule-good':'schedule-bad')+'">'+r.storage+' · '+(r.schedule||'manual')+' · '+(by[r.storage]?'OK':'FALTA')+'</span><button class="manual-button" onclick="manualBackup('+x.id+',\\''+r.storage+'\\')">▶</button></div>'}).join('');return'<details class="schedule-menu"><summary><span class="schedule-status '+(complete?'schedule-good':'schedule-bad')+'">'+(complete?'OK':'INCOMPLETO')+' · '+rules.length+' reglas</span></summary><div class="schedule-popup">'+lines+'</div></details>'}
function row(x){var found=x.expected.filter(function(s){return x.copies.some(function(c){return c.storage===s})}).length,ok=found===x.expected.length;return'<tr><td>'+x.id+'</td><td><strong>'+x.name+'</strong><br><span class="small">'+x.type.toUpperCase()+' · '+x.status+'</span></td><td>'+(ok?'<span class="good">OK</span>':'<span class="bad">INCOMPLETO</span>')+'<br><span class="small">'+found+'/'+x.expected.length+' destinos</span></td><td>'+copyCell(x)+'</td><td>'+snapshotCell(x)+'</td><td>'+scheduleCell(x)+'</td></tr>'}
'''
HTML = HTML.replace(old_row, new_row)
# Evita las comillas anidadas del onclick: además de ser más robusto, permite
# que el mismo control funcione igual en Safari y en navegadores de escritorio.
HTML = HTML.replace("onclick=\"manualBackup('+x.id+',\\\\''+r.storage+'\\\\')\"", "onclick=\"manualBackup(this.dataset.vmid,this.dataset.storage)\" data-vmid=\"'+x.id+'\" data-storage=\"'+r.storage+'\"")
class Handler(BaseHTTPRequestHandler):
    def json_response(self, data, status=200):
        payload = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(payload))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(payload)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_000_000: raise ValueError("payload demasiado grande")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_POST(self):
        global STATUS_CACHE, STATUS_CACHE_AT
        try:
            if self.path == "/api/policy":
                policy = self.read_json()
                if not isinstance(policy.get("guests"), dict): raise ValueError("inventario inválido")
                save_policy({"version": 1, "guests": policy["guests"]})
                STATUS_CACHE = None; STATUS_CACHE_AT = 0
                self.json_response({"ok": True, "message": "Reglas guardadas en el dashboard"}); return
            if self.path == "/api/sync":
                policy = live_policy({}, [])
                if POLICY_FILE.exists(): policy = json.loads(POLICY_FILE.read_text())
                changes = sync_policy(policy)
                STATUS_CACHE = None; STATUS_CACHE_AT = 0
                self.json_response({"ok": True, "changes": changes}); return
            if self.path == "/api/manual-backup":
                request = self.read_json()
                vmid = int(request.get("vmid")); storage = request.get("storage", "")
                if storage not in STORAGES or storage == "USB5Tb": raise ValueError("Destino no permitido")
                self.json_response({"ok": True, "task": manual_backup(vmid, storage)}); return
            if self.path == "/api/preview":
                policy = json.loads(POLICY_FILE.read_text()) if POLICY_FILE.exists() else {"version": 1, "guests": {}}
                self.json_response({"ok": True, "changes": sync_policy(policy, apply=False)}); return
            self.json_response({"error": "ruta no encontrada"}, 404)
        except Exception as error:
            self.json_response({"ok": False, "error": str(error)}, 500)

    def do_GET(self):
        global STATUS_CACHE, STATUS_CACHE_AT
        try:
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/status":
                with STATUS_LOCK:
                    now = time.time()
                    if STATUS_CACHE is not None and now - STATUS_CACHE_AT < 30:
                        data = STATUS_CACHE
                    else:
                        try:
                            data = backup_data()
                            STATUS_CACHE = data
                            STATUS_CACHE_AT = now
                        except Exception as refresh_error:
                            if STATUS_CACHE is None:
                                raise
                            data = dict(STATUS_CACHE)
                            data["stale"] = True
                            data["refresh_error"] = str(refresh_error)
                    payload = json.dumps(data).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8")
            elif path in ("/", "/index.html"):
                payload = HTML.encode(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            elif path == "/manifest.webmanifest":
                payload = Path("/opt/backup-dashboard/manifest.webmanifest").read_bytes(); self.send_response(200); self.send_header("Content-Type", "application/manifest+json; charset=utf-8")
            elif path == "/icon.svg":
                payload = Path("/opt/backup-dashboard/icon.svg").read_bytes(); self.send_response(200); self.send_header("Content-Type", "image/svg+xml")
            elif path == "/apple-touch-icon.png":
                payload = Path("/opt/backup-dashboard/apple-touch-icon.png").read_bytes(); self.send_response(200); self.send_header("Content-Type", "image/png")
            else: self.send_error(404); return
            self.send_header("Content-Length", str(len(payload))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(payload)
        except Exception as error: self.send_error(502, f"No se pudo consultar Proxmox: {error}")
    def log_message(self, *_): pass

ThreadingHTTPServer(("0.0.0.0", int(os.getenv("PORT", "8788"))), Handler).serve_forever()
