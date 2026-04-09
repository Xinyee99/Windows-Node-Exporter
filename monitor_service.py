import psutil
import time
import requests
import subprocess
import socket
import re
import logging
from datetime import datetime, timedelta

# ===== LOGGING =====
logging.basicConfig(
    filename=r"C:\monitor-agent\monitor.log",
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S'
)

# ===== EVENT ID MAP =====
EVENT_ID_MAP = {
    "1801":  "Secure Boot cert needs update",
    "10005": "DCOM service start failed",
    "7024":  "Service terminated with error",
    "7034":  "Service crashed unexpectedly",
    "7031":  "Service terminated unexpectedly",
    "41":    "System rebooted without clean shutdown",
    "6008":  "Unexpected shutdown",
    "1000":  "Application crash",
    "4625":  "Failed login attempt",
}

# ===== IP → HOST MAP =====
IP_NAME_MAP = {
    "10.230.134.90": "EWIN01",
    "10.230.135.102": "EWIN02",
    # "10.x.x.x": "ELV801",
}

# ===== CONFIG =====
CPU_WARN  = 80
CPU_CRIT  = 90
MEM_WARN  = 80
MEM_CRIT  = 90

WEBHOOK        = "https://open.larksuite.com/open-apis/bot/v2/hook/6c52b964-fc29-4e46-bf7a-859a9e237471"
CHECK_INTERVAL = 10
ALERT_COOLDOWN = 60

# ===== INIT HOST =====
def get_local_ip():
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2:
                    ip = addr.address
                    if not ip.startswith("127.") and not ip.startswith("169.254"):
                        return ip
    except:
        pass
    return "Unknown"

LOCAL_IP = get_local_ip()
HOST     = IP_NAME_MAP.get(LOCAL_IP, socket.gethostname())

# ===== STATE =====
cpu_count       = 0
mem_count       = 0
last_alert_time = datetime.min
was_alerting    = False  # 追踪是否曾经告警过

# ===== HELPERS =====
def get_level(cpu, mem):
    if cpu >= CPU_CRIT or mem >= MEM_CRIT:
        return "high"
    elif cpu >= CPU_WARN or mem >= MEM_WARN:
        return "warn"
    return None

def progress_bar(val, warn, crit, width=15):
    if val >= crit:
        icon = "🔴"
        fill_char = "█"
    elif val >= warn:
        icon = "🟡"
        fill_char = "█"
    else:
        icon = "🟢"
        fill_char = "█"
    filled = int(val / 100 * width)
    bar = fill_char * filled + "░" * (width - filled)
    return f"{icon} {bar} **{val:.1f}%**"

def get_severity(latest_error=None):
    if not latest_error:
        return "✅  **Severity:** NORMAL"
    lower = latest_error.lower()
    if any(k in lower for k in ['critical', 'fatal', 'crash']):
        return "🔴  **Severity:** CRITICAL"
    return "🟡  **Severity:** WARNING"

def get_system_info(latest_error=None):
    severity = get_severity(latest_error)
    lines = (
        f"🖥  **Host:** {HOST}\n"
        f"🌐  **IP:** {LOCAL_IP}\n"
        f"{severity}"
    )
    if latest_error:
        m = re.search(r'\[(\d+)\].*?—\s*(.+)', latest_error)
        if m:
            eid  = m.group(1)
            name = EVENT_ID_MAP.get(eid, m.group(2).strip()[:50])
            lines += f"\n⚠️  **Latest Error:** [{eid}] {name}"
        else:
            lines += f"\n⚠️  **Latest Error:** {latest_error[:60]}"
    return lines

def get_top_process():
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        pass
    time.sleep(1)

    skip = {'system idle process', 'system', 'registry', 'memory compression', ''}
    merged = {}
    for p in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
        try:
            name = (p.info['name'] or '').strip()
            cpu  = p.info['cpu_percent'] or 0
            mem  = p.info['memory_percent'] or 0
            if name.lower() in skip or cpu < 0.5:
                continue
            if name in merged:
                merged[name]['cpu'] += cpu
                merged[name]['mem'] += mem
            else:
                merged[name] = {'cpu': cpu, 'mem': mem}
        except:
            continue

    procs = sorted(merged.items(), key=lambda x: x[1]['cpu'], reverse=True)[:5]

    if not procs:
        return {"tag": "div", "text": {"tag": "lark_md", "content": "  (无活跃进程)"}}

    col_names = "\n".join([
        f"• {(n[:20]+'..') if len(n)>22 else n}"
        for n, v in procs
    ])
    col_cpu = "\n".join([f"{v['cpu']:.1f}%" for n, v in procs])
    col_mem = "\n".join([f"{round(v['mem'],1):.1f}%" for n, v in procs])

    return {
        "tag": "column_set",
        "flex_mode": "none",
        "background_style": "default",
        "columns": [
            {
                "tag": "column", "width": "weighted", "weight": 4,
                "elements": [{"tag": "div", "text": {"tag": "lark_md", "content": f"**Process**\n{col_names}"}}]
            },
            {
                "tag": "column", "width": "weighted", "weight": 2,
                "elements": [{"tag": "div", "text": {"tag": "lark_md", "content": f"**CPU**\n{col_cpu}"}}]
            },
            {
                "tag": "column", "width": "weighted", "weight": 2,
                "elements": [{"tag": "div", "text": {"tag": "lark_md", "content": f"**MEM**\n{col_mem}"}}]
            },
        ]
    }

def get_gpu_usage():
    try:
        result = subprocess.check_output(
            'nvidia-smi --query-compute-apps=process_name,used_memory --format=csv,noheader',
            shell=True, stderr=subprocess.DEVNULL
        ).decode().strip()
        if not result:
            return ["  🟢 No GPU processes"]
        lines = []
        for line in result.splitlines():
            parts = line.split(',')
            if len(parts) == 2:
                mem = parts[1].strip()
                if 'N/A' in mem:
                    continue
                name = parts[0].strip().split('\\')[-1]
                lines.append(f"  • {name}  {mem}")
        return lines if lines else ["  🟢 No GPU processes"]
    except:
        return ["  ⚠️ No GPU / fetch failed"]

def get_event_logs():
    try:
        ps_script = r"""
$events = Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2} -MaxEvents 3 -ErrorAction SilentlyContinue
if ($null -eq $events) {
    Write-Output "NONE"
} else {
    foreach ($e in $events) {
        $msg = $e.Message.Substring(0, [Math]::Min(60, $e.Message.Length)).Replace("`n"," ")
        Write-Output ($e.TimeCreated.ToString("MM/dd HH:mm") + "|" + $e.Id + "|" + $msg)
    }
}
"""
        ps_path = r"C:\monitor-agent\get_events.ps1"
        with open(ps_path, 'w', encoding='utf-8') as f:
            f.write(ps_script)

        result = subprocess.check_output(
            f'powershell -ExecutionPolicy Bypass -File "{ps_path}"',
            shell=True, stderr=subprocess.DEVNULL, timeout=15
        ).decode(errors='ignore').strip()

        if not result or result == 'NONE':
            return ["  🟢 No error events"]

        lines = []
        for line in result.splitlines():
            line = line.strip()
            if '|' in line:
                parts = line.split('|', 2)
                t   = parts[0].strip()
                eid = parts[1].strip()
                msg = parts[2].strip() if len(parts) > 2 else ''
                desc = EVENT_ID_MAP.get(eid, msg[:50])
                lines.append(f"  • [{eid}] {t} — {desc}...")
        return lines[:3] if lines else ["  🟢 No error events"]
    except Exception as e:
        return [f"  ⚠️ Fetch failed: {str(e)[:60]}"]

# ===== 新版 get_edge_memory（方案2：CDP + WebSocket per-tab JS Heap） =====
def get_edge_memory():
    import websocket
    import json as _json

    def get_tab_js_memory(ws_url, timeout=3):
        """通过 WebSocket 拿单个 tab 的 JS Heap 内存（MB）"""
        try:
            ws = websocket.create_connection(
                ws_url, timeout=timeout,
                header=["Origin: http://localhost:9222"]
            )
            ws.send(_json.dumps({"id": 1, "method": "Performance.enable"}))
            ws.recv()
            ws.send(_json.dumps({"id": 2, "method": "Performance.getMetrics"}))
            raw = ws.recv()
            ws.close()
            data = _json.loads(raw)
            metrics = {m['name']: m['value'] for m in data.get('result', {}).get('metrics', [])}
            heap = metrics.get('JSHeapUsedSize', 0)
            return heap / 1024 / 1024  # bytes → MB
        except:
            return None

    # Step 1: 获取所有 msedge 进程总内存（作为 fallback 和 Total 显示用）
    total_mem = 0
    for p in psutil.process_iter(['name', 'memory_info']):
        try:
            if 'msedge' in (p.info['name'] or '').lower():
                total_mem += p.info['memory_info'].rss / 1024 / 1024
        except:
            continue

    if total_mem == 0:
        return None

    # Step 2: 从 CDP /json 拿标签页列表
    try:
        resp = requests.get("http://localhost:9222/json", timeout=3)
        tabs = resp.json()
    except:
        icon = '🔴' if total_mem > 500 else '🟡' if total_mem > 200 else '🟢'
        return {
            "tag": "div",
            "text": {"tag": "lark_md", "content": f"{icon} Edge (total): **{total_mem:.0f} MB**\n_(Tab details unavailable)_"}
        }

    # Step 3: 只取 type == "page"，过滤掉 localhost:9222 自身
    pages = [
        t for t in tabs
        if t.get('type') == 'page'
        and 'localhost:9222' not in t.get('url', '')
    ]

    if not pages:
        icon = '🔴' if total_mem > 500 else '🟡' if total_mem > 200 else '🟢'
        return {
            "tag": "div",
            "text": {"tag": "lark_md", "content": f"{icon} Edge (total): **{total_mem:.0f} MB** (no open tabs)"}
        }

    # Step 4: 逐个 tab 通过 WebSocket 拿真实 JS Heap 内存，最多取5个
    display = []
    for t in pages[:5]:
        title  = (t.get('title') or t.get('url') or 'Unknown Tab')
        title  = title[:30] + '..' if len(title) > 32 else title
        ws_url = t.get('webSocketDebuggerUrl', '')
        mem    = get_tab_js_memory(ws_url) if ws_url else None

        if mem is None:
            mem_str = '—'
            icon    = '⚪'
        else:
            icon    = '🔴' if mem > 300 else '🟡' if mem > 100 else '🟢'
            mem_str = f"**{mem:.0f} MB**"

        display.append((f"{icon} {title}", mem_str))

    # Step 5: 构建 Lark card columns
    total_icon  = '🔴' if total_mem > 1000 else '🟡' if total_mem > 500 else '🟢'
    col_titles  = "\n".join([t for t, m in display]) + f"\n\n**Total ({len(pages)} tabs)**"
    col_mems    = "\n".join([m for t, m in display]) + f"\n\n{total_icon} **{total_mem:.0f} MB**"

    return {
        "tag": "column_set",
        "flex_mode": "none",
        "background_style": "default",
        "columns": [
            {
                "tag": "column", "width": "weighted", "weight": 5,
                "elements": [{"tag": "div", "text": {"tag": "lark_md", "content": f"**Tab Title**\n{col_titles}"}}]
            },
            {
                "tag": "column", "width": "weighted", "weight": 2,
                "elements": [{"tag": "div", "text": {"tag": "lark_md", "content": f"**Memory**\n{col_mems}"}}]
            },
        ]
    }

def send_resolved(cpu, mem):
    card = {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": f"✅ RESOLVED — {HOST}"},
                "template": "green"
            },
            "elements": [
                {"tag": "div", "text": {"tag": "lark_md", "content":
                    f"🕐 **{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}**\n\n"
                    f"🖥  **Host:** {HOST}\n"
                    f"🌐  **IP:** {LOCAL_IP}\n\n"
                    f"✅  System has returned to normal\n"
                    f"💻  CPU: **{cpu:.1f}%**\n"
                    f"🧠  Memory: **{mem:.1f}%**"
                }}
            ]
        }
    }
    requests.post(WEBHOOK, json=card)

def send_lark_alert(data, level):
    global last_alert_time
    if datetime.now() - last_alert_time < timedelta(seconds=ALERT_COOLDOWN):
        return

    color = "red"    if level == "high" else "yellow"
    badge = "🔴 CRITICAL ALERT" if level == "high" else "🟡 WARNING ALERT"

    def block(content):
        return {"tag": "div", "text": {"tag": "lark_md", "content": content}}

    def hr():
        return {"tag": "hr"}

    elements = [
        block(f"🕐 **{data['time']}**"),
        hr(),
        block(data['sysinfo']),
        hr(),
        block(
            f"**💻 CPU**\n{data['cpu_bar']}\n\n"
            f"**🧠 Memory**\n{data['mem_bar']}"
        ),
        hr(),
        block("**📊 Top Process (by CPU)**"),
        data['top'],
        hr(),
        block("**🌐 Edge Memory**"),
    ]

    if data['edge'] is None:
        elements.append(block("  🟢 No Edge processes"))
    else:
        elements.append(data['edge'])

    elements += [
        hr(),
        block("**🎮 GPU**\n" + "\n".join(data['gpu'])),
        hr(),
        block("**📋 Event Log**\n" + "\n".join(data['event'])),
    ]

    card = {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": f"{badge} — {HOST}"},
                "template": color
            },
            "elements": elements
        }
    }

    requests.post(WEBHOOK, json=card)
    last_alert_time = datetime.now()

# ===== MAIN LOOP =====
while True:
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent
    level = get_level(cpu, mem)

    logging.info(f"host={HOST} cpu={cpu:.1f} mem={mem:.1f} level={level or 'normal'}")

    if level:
        cpu_count += 1
        mem_count += 1
    else:
        # 如果之前在告警状态，现在恢复正常 → 发 RESOLVED
        if was_alerting:
            send_resolved(cpu, mem)
            was_alerting = False
        cpu_count = 0
        mem_count = 0

    if cpu_count >= 3 or mem_count >= 3:
        event_lines = get_event_logs()
        latest_error = None
        if event_lines and "🟢" not in event_lines[0] and "⚠️" not in event_lines[0]:
            latest_error = event_lines[0].strip().lstrip("• ")

        data = {
            "time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu":     cpu,
            "memory":  mem,
            "cpu_bar": progress_bar(cpu, CPU_WARN, CPU_CRIT),
            "mem_bar": progress_bar(mem, MEM_WARN, MEM_CRIT),
            "sysinfo": get_system_info(latest_error),
            "top":     get_top_process(),
            "gpu":     get_gpu_usage(),
            "event":   event_lines,
            "edge":    get_edge_memory(),
        }
        send_lark_alert(data, level)
        was_alerting = True
        cpu_count = 0
        mem_count = 0