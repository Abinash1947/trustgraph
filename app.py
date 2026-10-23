"""
TRUSTGRAPH // CYBER INTELLIGENCE COMMAND
Graph analytics & fraud ring surveillance dashboard (Streamlit).

Run:   streamlit run trustgraph_app.py
Deps:  pip install streamlit requests pyvis pandas

If the backend API is offline, the dashboard falls back to a clearly-labelled
LOCAL SIMULATION engine so the UI remains fully demonstrable.
"""

import csv
import io
import random
from collections import defaultdict, deque
from datetime import datetime, timezone

import pandas as pd
import requests
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

# ============================================================
# CONFIG
# ============================================================
DEFAULT_API_URL = "http://127.0.0.1:8000"
API_TIMEOUT = 10

ACTION_WEIGHT = {
    "LOGIN": 5,
    "PASSWORD_RESET": 15,
    "TX_INITIATE": 20,
    "DEVICE_BIND": 25,
}

st.set_page_config(
    page_title="TRUSTGRAPH // CYBER INTELLIGENCE COMMAND",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# CINEMATIC CSS
# ============================================================
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@500;700;900&display=swap');

:root {
    --bg: #020617;
    --panel: #070b14;
    --panel2: #0a1020;
    --green: #00ff66;
    --cyan: #00e5ff;
    --red: #ff0055;
    --amber: #ffb800;
    --text: #7dd3fc;
    --dim: #475569;
}

/* ---------- base ---------- */
.stApp {
    background:
        radial-gradient(ellipse at 20% 0%, rgba(0,255,102,0.07), transparent 50%),
        radial-gradient(ellipse at 90% 100%, rgba(0,229,255,0.07), transparent 50%),
        linear-gradient(rgba(0,255,102,0.035) 1px, transparent 1px) 0 0 / 100% 42px,
        linear-gradient(90deg, rgba(0,255,102,0.035) 1px, transparent 1px) 0 0 / 42px 100%,
        var(--bg);
    color: var(--text);
    font-family: 'Share Tech Mono', 'Courier New', monospace;
}

/* CRT scanlines + vignette overlay */
.stApp::before {
    content: "";
    position: fixed; inset: 0;
    pointer-events: none;
    z-index: 9999;
    background:
        repeating-linear-gradient(to bottom,
            rgba(0,0,0,0) 0px, rgba(0,0,0,0) 2px,
            rgba(0,0,0,0.18) 3px, rgba(0,0,0,0) 4px),
        radial-gradient(ellipse at center, transparent 60%, rgba(0,0,0,0.55) 100%);
}
/* moving scan beam */
.stApp::after {
    content: "";
    position: fixed; left: 0; right: 0; top: -20%;
    height: 18%;
    pointer-events: none;
    z-index: 9998;
    background: linear-gradient(to bottom, transparent, rgba(0,255,102,0.06), transparent);
    animation: beam 7s linear infinite;
}
@keyframes beam { to { top: 120%; } }

header[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 1.2rem; max-width: 1500px; }

h1, h2, h3, h4 {
    font-family: 'Orbitron', 'Courier New', monospace !important;
    color: var(--green) !important;
    letter-spacing: 2px;
    text-shadow: 0 0 10px rgba(0,255,102,0.45);
}
p, label, span, div, li, td, th, code {
    font-family: 'Share Tech Mono', 'Courier New', monospace;
}

/* ---------- hero banner ---------- */
.hero {
    position: relative;
    border: 1px solid rgba(0,255,102,0.5);
    background: linear-gradient(135deg, rgba(0,255,102,0.08), rgba(0,229,255,0.05) 60%, transparent);
    padding: 22px 28px;
    border-radius: 6px;
    margin-bottom: 14px;
    box-shadow: 0 0 30px rgba(0,255,102,0.12), inset 0 0 40px rgba(0,255,102,0.04);
    overflow: hidden;
}
.hero::before, .hero::after {
    content: ""; position: absolute; width: 22px; height: 22px;
    border: 2px solid var(--cyan);
}
.hero::before { top: 6px; left: 6px; border-right: none; border-bottom: none; }
.hero::after  { bottom: 6px; right: 6px; border-left: none; border-top: none; }
.hero-title {
    font-family: 'Orbitron', monospace;
    font-weight: 900;
    font-size: 2rem;
    color: var(--green);
    letter-spacing: 4px;
    text-shadow: 0 0 14px rgba(0,255,102,0.7);
    animation: flicker 6s infinite;
}
.hero-title .glitch { position: relative; display: inline-block; }
.hero-title .glitch::before, .hero-title .glitch::after {
    content: attr(data-text);
    position: absolute; left: 0; top: 0; width: 100%;
    overflow: hidden; opacity: .75;
}
.hero-title .glitch::before { color: var(--red);  left: 2px;  animation: glitch1 3.2s infinite linear alternate-reverse; clip-path: inset(0 0 55% 0); }
.hero-title .glitch::after  { color: var(--cyan); left: -2px; animation: glitch2 2.7s infinite linear alternate-reverse; clip-path: inset(55% 0 0 0); }
@keyframes glitch1 { 0%,92%{transform:translate(0)} 94%{transform:translate(-3px,1px)} 96%{transform:translate(3px,-1px)} 100%{transform:translate(0)} }
@keyframes glitch2 { 0%,90%{transform:translate(0)} 93%{transform:translate(3px,-1px)} 97%{transform:translate(-3px,1px)} 100%{transform:translate(0)} }
@keyframes flicker { 0%,19%,21%,60%,62%,100%{opacity:1} 20%,61%{opacity:.82} }
.hero-sub { color: var(--cyan); letter-spacing: 3px; font-size: .85rem; margin-top: 4px; }
.hero-meta { color: var(--dim); font-size: .75rem; margin-top: 10px; }
.cursor::after { content: "█"; color: var(--green); animation: blink 1s steps(2) infinite; margin-left: 4px; }
@keyframes blink { 50% { opacity: 0; } }

/* ---------- ticker ---------- */
.ticker-wrap {
    border-top: 1px solid rgba(0,255,102,0.35);
    border-bottom: 1px solid rgba(0,255,102,0.35);
    background: rgba(0,255,102,0.04);
    overflow: hidden; white-space: nowrap;
    padding: 6px 0; margin-bottom: 16px;
}
.ticker {
    display: inline-block; padding-left: 100%;
    animation: scroll 55s linear infinite;
    color: var(--amber); font-size: .8rem; letter-spacing: 1px;
}
.ticker b { color: var(--red); }
@keyframes scroll { to { transform: translateX(-100%); } }

/* ---------- cards ---------- */
.kpi {
    background: linear-gradient(160deg, var(--panel2), var(--panel));
    border: 1px solid rgba(0,255,102,0.45);
    border-radius: 6px;
    padding: 14px 16px;
    box-shadow: 0 0 18px rgba(0,255,102,0.10);
    position: relative; overflow: hidden;
    transition: transform .2s, box-shadow .2s;
}
.kpi:hover { transform: translateY(-2px); box-shadow: 0 0 26px rgba(0,255,102,0.30); }
.kpi::before {
    content:""; position:absolute; left:0; top:0; bottom:0; width:3px;
    background: var(--accent, var(--green));
    box-shadow: 0 0 12px var(--accent, var(--green));
}
.kpi-label { color: var(--dim); font-size: .7rem; letter-spacing: 2px; text-transform: uppercase; }
.kpi-value {
    font-family: 'Orbitron', monospace; font-size: 1.9rem; font-weight: 700;
    color: var(--accent, var(--green));
    text-shadow: 0 0 10px var(--accent, var(--green));
}
.kpi-sub { color: var(--text); font-size: .72rem; opacity: .8; }

.report-box {
    background: linear-gradient(160deg, var(--panel2), var(--panel));
    border: 1px solid var(--green);
    border-left: 4px solid var(--green);
    padding: 22px; border-radius: 6px; margin-bottom: 20px;
    box-shadow: 0 0 20px rgba(0,255,102,0.15);
}
.report-box p, .report-box li { color: #bae6fd; }

.panel-title {
    font-family:'Orbitron',monospace; color: var(--cyan);
    letter-spacing: 3px; font-size: .85rem; margin: 6px 0 10px 0;
    border-bottom: 1px dashed rgba(0,229,255,0.35); padding-bottom: 4px;
}

/* ---------- risk gauge ---------- */
.gauge {
    background: var(--panel); border: 1px solid var(--gc, var(--green));
    border-radius: 6px; padding: 14px; text-align: center;
    box-shadow: 0 0 20px var(--gcs, rgba(0,255,102,.2));
}
.gauge-ring {
    width: 150px; height: 150px; border-radius: 50%; margin: 6px auto 10px auto;
    background: conic-gradient(var(--gc) calc(var(--pct) * 1%), #0f172a 0);
    display: flex; align-items: center; justify-content: center;
    box-shadow: 0 0 25px var(--gcs);
}
.gauge-inner {
    width: 116px; height: 116px; border-radius: 50%; background: var(--panel);
    display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.gauge-num { font-family:'Orbitron',monospace; font-size: 2.1rem; color: var(--gc); text-shadow: 0 0 12px var(--gc); }
.gauge-lbl { color: var(--dim); font-size: .65rem; letter-spacing: 2px; }
.gauge-status { font-family:'Orbitron',monospace; letter-spacing: 3px; color: var(--gc); font-size: 1rem; }

/* ---------- feed ---------- */
.feed-row {
    border-left: 3px solid var(--fc, var(--green));
    background: rgba(255,255,255,0.02);
    padding: 6px 10px; margin-bottom: 5px; font-size: .78rem;
    animation: slidein .4s ease-out;
}
.feed-row .t { color: var(--dim); }
.feed-row .s { color: var(--fc); font-weight: bold; }
@keyframes slidein { from { opacity: 0; transform: translateX(-12px);} to { opacity: 1; transform: none; } }

.badge {
    display:inline-block; padding: 2px 8px; border-radius: 3px; font-size: .7rem;
    letter-spacing: 1px; border: 1px solid currentColor; margin-right: 6px;
}
.pulse-dot {
    display:inline-block; width:9px; height:9px; border-radius:50%;
    background: var(--dc, var(--green)); box-shadow: 0 0 10px var(--dc, var(--green));
    animation: pulse 1.4s infinite; margin-right: 6px;
}
@keyframes pulse { 0%{opacity:1; transform:scale(1)} 50%{opacity:.35; transform:scale(1.4)} 100%{opacity:1; transform:scale(1)} }

/* ---------- widgets ---------- */
.stButton > button, .stFormSubmitButton > button, .stDownloadButton > button {
    background: linear-gradient(180deg, #0b1322, #070b14);
    color: var(--green);
    border: 1px solid var(--green);
    font-family: 'Share Tech Mono', monospace;
    font-weight: bold; letter-spacing: 1px;
    border-radius: 4px; width: 100%;
    transition: all .2s;
}
.stButton > button:hover, .stFormSubmitButton > button:hover, .stDownloadButton > button:hover {
    background: var(--green); color: var(--bg);
    box-shadow: 0 0 22px var(--green);
}
.stTextInput input, .stNumberInput input, .stSelectbox div[data-baseweb="select"] > div, .stTextArea textarea {
    background-color: #050914 !important;
    color: var(--cyan) !important;
    border: 1px solid rgba(0,255,102,0.35) !important;
    font-family: 'Share Tech Mono', monospace !important;
}
.stTextInput input:focus { border-color: var(--green) !important; box-shadow: 0 0 10px rgba(0,255,102,.5) !important; }

section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #030816, #020617);
    border-right: 1px solid rgba(0,255,102,0.35);
}
div[data-testid="stMetric"] {
    background: var(--panel); border: 1px solid rgba(0,255,102,0.35);
    padding: 10px 14px; border-radius: 6px;
}
div[data-testid="stMetricValue"] { color: var(--green); font-family: 'Orbitron', monospace; }
div[data-testid="stExpander"] { border: 1px solid rgba(0,255,102,0.3); border-radius: 6px; background: var(--panel); }
.stTabs [data-baseweb="tab"] { color: var(--dim); font-family: 'Share Tech Mono', monospace; }
.stTabs [aria-selected="true"] { color: var(--green) !important; }
hr { border-color: rgba(0,255,102,0.25) !important; }

::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-thumb { background: rgba(0,255,102,0.4); border-radius: 4px; }
::-webkit-scrollbar-track { background: #020617; }
</style>
""",
    unsafe_allow_html=True,
)

# ============================================================
# SESSION STATE
# ============================================================
ss = st.session_state
ss.setdefault("events", [])  # telemetry events
ss.setdefault("txs", [])  # transactions
ss.setdefault("booted", False)
ss.setdefault("api_url", DEFAULT_API_URL)


# ============================================================
# HELPERS
# ============================================================
def utc_now():
    return datetime.now(timezone.utc)


def stamp():
    return utc_now().strftime("%Y-%m-%d %H:%M:%S")


def status_for(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "ELEVATED"
    return "LOW"


STATUS_COLOR = {
    "CRITICAL": "#ff0055",
    "HIGH": "#ff6a00",
    "ELEVATED": "#ffb800",
    "LOW": "#00ff66",
}


def color_for_score(score):
    return STATUS_COLOR[status_for(score)]


def api_get(endpoint):
    try:
        r = requests.get(f"{ss.api_url}{endpoint}", timeout=API_TIMEOUT)
        r.raise_for_status()
        return r.json(), None
    except requests.RequestException as exc:
        return None, str(exc)
    except ValueError:
        return None, "The backend returned invalid JSON."


def api_post(endpoint, payload):
    try:
        r = requests.post(f"{ss.api_url}{endpoint}", json=payload, timeout=API_TIMEOUT)
        r.raise_for_status()
        return r.json(), None
    except requests.RequestException as exc:
        details = ""
        if getattr(exc, "response", None) is not None:
            details = f" | Response: {exc.response.text[:500]}"
        return None, f"{exc}{details}"
    except ValueError:
        return None, "The backend returned invalid JSON."


@st.cache_data(ttl=5, show_spinner=False)
def _health(url):
    try:
        r = requests.get(f"{url}/", timeout=3)
        r.raise_for_status()
        return True
    except requests.RequestException:
        return False


# ---------- local simulation engine (used when backend is offline) ----------
def local_assess(user, device, ip, action):
    """Heuristic graph-based risk score computed from this session's events."""
    users_on_device = {e["user"] for e in ss.events if e["device"] == device} - {user}
    users_on_ip = {e["user"] for e in ss.events if e["ip"] == ip} - {user}
    score = ACTION_WEIGHT.get(action, 5)
    chain = [f"Action vector '{action}' carries base weight {score}."]
    if users_on_device:
        add = min(60, 25 * len(users_on_device))
        score += add
        chain.append(
            f"Device '{device}' is shared with {len(users_on_device)} other account(s): "
            f"{', '.join(sorted(users_on_device))} (+{add})."
        )
    if users_on_ip:
        add = min(25, 8 * len(users_on_ip))
        score += add
        chain.append(f"IP {ip} is reused by {len(users_on_ip)} other account(s) (+{add}).")
    if not users_on_device and not users_on_ip:
        chain.append("No shared infrastructure observed in the current session graph.")
    score = min(100, score)
    return {
        "entity_risk_score": score,
        "risk_status": status_for(score),
        "explainability_payload": {"reasoning_chain": chain},
    }


def find_cycles(txs, max_len=6):
    """Detect simple directed cycles in the transaction graph."""
    adj = defaultdict(set)
    for t in txs:
        if t["sender"] != t["receiver"]:
            adj[t["sender"]].add(t["receiver"])
    found = set()

    def dfs(start, node, path):
        if len(path) > max_len:
            return
        for nxt in adj[node]:
            if nxt == start and len(path) >= 2:
                i = path.index(min(path))
                found.add(tuple(path[i:] + path[:i]))
            elif nxt not in path:
                dfs(start, nxt, path + [nxt])

    for n in list(adj):
        dfs(n, n, [n])
    return [list(c) for c in sorted(found, key=lambda c: (len(c), c))]


def build_entity_graph():
    """Return (nodes, edges) derived from the telemetry events."""
    nodes, edges = {}, set()
    for e in ss.events:
        nodes[e["user"]] = "user"
        nodes[e["device"]] = "device"
        nodes[e["ip"]] = "ip"
        edges.add((e["user"], e["device"], "USED_DEVICE"))
        edges.add((e["device"], e["ip"], "CONNECTED_VIA"))
    return nodes, edges


def neighbors_map(edges):
    adj = defaultdict(set)
    for a, b, _ in edges:
        adj[a].add(b)
        adj[b].add(a)
    return adj


def blast_radius(start, adj, hops=2):
    seen = {start: 0}
    q = deque([start])
    while q:
        n = q.popleft()
        if seen[n] >= hops:
            continue
        for m in adj[n]:
            if m not in seen:
                seen[m] = seen[n] + 1
                q.append(m)
    return seen


def shared_device_clusters():
    """Devices linked to >= 2 distinct users."""
    dev_users = defaultdict(set)
    for e in ss.events:
        dev_users[e["device"]].add(e["user"])
    return {d: sorted(u) for d, u in dev_users.items() if len(u) >= 2}


def new_network(height="520px"):
    net = Network(
        height=height, width="100%", bgcolor="#050914",
        font_color="#7dd3fc", directed=False, notebook=False,
    )
    net.barnes_hut(
        gravity=-3500, central_gravity=0.4, spring_length=110,
        spring_strength=0.04, damping=0.09,
    )
    return net


NODE_STYLE = {
    "user": dict(shape="dot", size=24, color="#00ff66"),
    "device": dict(shape="triangle", size=30, color="#ff0055"),
    "ip": dict(shape="square", size=22, color="#00e5ff"),
}


def render_graph(nodes, edges, highlight=None, height="520px"):
    net = new_network(height)
    hl = highlight or {}
    cluster_devices = set(shared_device_clusters())
    for n, kind in nodes.items():
        style = dict(NODE_STYLE[kind])
        if kind == "device" and n not in cluster_devices:
            style["color"] = "#ffb800"
        if hl and n not in hl:
            style["color"] = "#1e293b"
        if hl and hl.get(n) == 0:
            style["size"] += 10
            style["color"] = "#ffffff"
        net.add_node(n, label=n, title=f"{kind.upper()}: {n}", **style)
    for a, b, lbl in edges:
        dim = bool(hl) and (a not in hl or b not in hl)
        net.add_edge(a, b, label="" if dim else lbl,
                     color="#1e293b" if dim else "#475569", width=1 if dim else 2)
    components.html(net.generate_html(), height=int(height.replace("px", "")) + 20, scrolling=True)


def kpi(label, value, sub="", accent="#00ff66"):
    st.markdown(
        f'<div class="kpi" style="--accent:{accent}">'
        f'<div class="kpi-label">{label}</div>'
        f'<div class="kpi-value">{value}</div>'
        f'<div class="kpi-sub">{sub}</div></div>',
        unsafe_allow_html=True,
    )


def gauge(score, status):
    c = STATUS_COLOR.get(status, "#00ff66")
    st.markdown(
        f"""<div class="gauge" style="--gc:{c}; --gcs:{c}55; --pct:{score}">
        <div class="gauge-lbl">ENTITY RISK SCORE</div>
        <div class="gauge-ring"><div class="gauge-inner">
            <div class="gauge-num">{score}</div><div class="gauge-lbl">/ 100</div>
        </div></div>
        <div class="gauge-status">{status}</div></div>""",
        unsafe_allow_html=True,
    )


def log_event(user, device, ip, action, score, status, source):
    ss.events.append({
        "ts": stamp(), "user": user, "device": device, "ip": ip,
        "action": action, "score": score, "status": status, "source": source,
    })


def load_demo_scenario():
    demo = [
        ("user_201", "device_MALICIOUS_1", "10.0.0.99", "LOGIN"),
        ("user_202", "device_MALICIOUS_1", "10.0.0.99", "PASSWORD_RESET"),
        ("user_203", "device_MALICIOUS_1", "10.0.0.99", "DEVICE_BIND"),
        ("user_310", "device_A77", "172.16.4.8", "LOGIN"),
        ("user_311", "device_B12", "172.16.4.9", "TX_INITIATE"),
    ]
    for u, d, i, a in demo:
        a_ = local_assess(u, d, i, a)
        log_event(u, d, i, a, a_["entity_risk_score"], a_["risk_status"], "DEMO")
    for s, r, amt in [("trader_X", "trader_Y", 5000), ("trader_Y", "trader_Z", 4900),
                      ("trader_Z", "trader_X", 4800), ("trader_A", "trader_B", 1200)]:
        ss.txs.append({"ts": stamp(), "sender": s, "receiver": r, "amount": float(amt), "source": "DEMO"})


# ============================================================
# SIDEBAR
# ============================================================
st.sidebar.markdown("## 🛡️ TRUSTGRAPH // SEC-OPS")
st.sidebar.markdown(f"`{stamp()} UTC`")

with st.sidebar.expander("⚙️ BACKEND LINK", expanded=False):
    ss.api_url = st.text_input("API Base URL", value=ss.api_url).rstrip("/")
    if st.button("Re-check link"):
        _health.clear()

backend_online = _health(ss.api_url)
if backend_online:
    st.sidebar.markdown(
        '<span class="pulse-dot"></span> **GRAPH ENGINE: ONLINE**', unsafe_allow_html=True)
else:
    st.sidebar.markdown(
        '<span class="pulse-dot" style="--dc:#ff0055"></span> **GRAPH ENGINE: OFFLINE**',
        unsafe_allow_html=True)
    st.sidebar.caption("Local simulation engine active. Results are NOT from the backend.")

st.sidebar.markdown("---")
st.sidebar.markdown("### 📡 INTELLIGENCE FEEDS")
MODES = [
    "Command Overview",
    "Shared Infrastructure (Fraud Rings)",
    "Circular Wash-Trading",
    "Threat Hunt Console",
    "Audit Log & Export",
    "Executive Incident Brief",
]
active_mode = st.sidebar.radio("Select feed", MODES, label_visibility="collapsed")

st.sidebar.markdown("---")
st.sidebar.markdown("### 🎚️ DETECTION POLICY")
alert_threshold = st.sidebar.slider("Alert threshold (risk score)", 10, 100, 50, 5)
st.sidebar.caption("Events at or above this score are escalated in the feed.")

st.sidebar.markdown("---")
c1, c2 = st.sidebar.columns(2)
if c1.button("Load demo"):
    load_demo_scenario()
    st.toast("Demo scenario loaded", icon="🛰️")
if c2.button("Purge data"):
    ss.events.clear()
    ss.txs.clear()
    st.toast("Session data purged", icon="🧹")

# ============================================================
# HERO + TICKER
# ============================================================
total_events = len(ss.events)
critical_cnt = sum(1 for e in ss.events if e["score"] >= 75)
cycles_now = find_cycles(ss.txs)
clusters_now = shared_device_clusters()

if not ss.booted:
    ss.booted = True
    st.toast("Secure channel established. Welcome, analyst.", icon="🔐")

st.markdown(
    f"""
<div class="hero">
  <div class="hero-title"><span class="glitch" data-text="⚡ TRUSTGRAPH // THREAT INTEL COMMAND">⚡ TRUSTGRAPH // THREAT INTEL COMMAND</span></div>
  <div class="hero-sub">AUTONOMOUS GRAPH ANALYTICS &nbsp;•&nbsp; FRAUD RING SURVEILLANCE &nbsp;•&nbsp; WASH-TRADE DETECTION</div>
  <div class="hero-meta cursor">SESSION {abs(hash(ss.api_url)) % 99999:05d} &nbsp;|&nbsp; CLEARANCE: ANALYST-L3 &nbsp;|&nbsp; MODE: {active_mode.upper()}</div>
</div>
<div class="ticker-wrap"><div class="ticker">
  ▓ EVENTS INGESTED: <b>{total_events}</b> &nbsp;&nbsp;▓ CRITICAL: <b>{critical_cnt}</b>
  &nbsp;&nbsp;▓ SHARED-DEVICE CLUSTERS: <b>{len(clusters_now)}</b>
  &nbsp;&nbsp;▓ ACTIVE WASH-TRADE RINGS: <b>{len(cycles_now)}</b>
  &nbsp;&nbsp;▓ ENGINE: <b>{'ONLINE' if backend_online else 'SIMULATION'}</b>
  &nbsp;&nbsp;▓ ALERT THRESHOLD: <b>{alert_threshold}</b>
  &nbsp;&nbsp;▓ ALL TRAFFIC ENCRYPTED // TLS 1.3 &nbsp;&nbsp;▓ ZERO-TRUST POLICY ENFORCED
</div></div>
""",
    unsafe_allow_html=True,
)

# ============================================================
# MODE: COMMAND OVERVIEW
# ============================================================
if active_mode == "Command Overview":
    avg = round(sum(e["score"] for e in ss.events) / total_events, 1) if total_events else 0
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        kpi("Events Ingested", total_events, "telemetry records", "#00e5ff")
    with k2:
        kpi("Critical Alerts", critical_cnt, "score ≥ 75", "#ff0055")
    with k3:
        kpi("Fraud Clusters", len(clusters_now), "shared-device rings", "#ff6a00")
    with k4:
        kpi("Wash-Trade Rings", len(cycles_now), "directed cycles", "#ffb800")
    with k5:
        kpi("Avg Risk", avg, "session mean", color_for_score(avg))

    st.markdown("")
    left, right = st.columns([1.5, 1])

    with left:
        st.markdown('<div class="panel-title">▌ RISK TIMELINE</div>', unsafe_allow_html=True)
        if ss.events:
            df = pd.DataFrame(ss.events)
            df["#"] = range(1, len(df) + 1)
            st.line_chart(df.set_index("#")["score"], height=240, color="#00ff66")
        else:
            st.info("No telemetry yet. Use **Load demo** in the sidebar or ingest events.")

        st.markdown('<div class="panel-title">▌ ACTION VECTOR DISTRIBUTION</div>', unsafe_allow_html=True)
        if ss.events:
            counts = pd.Series([e["action"] for e in ss.events]).value_counts()
            st.bar_chart(counts, height=200, color="#00e5ff")

    with right:
        st.markdown('<div class="panel-title">▌ LIVE THREAT FEED</div>', unsafe_allow_html=True)
        if ss.events:
            for e in reversed(ss.events[-10:]):
                fc = color_for_score(e["score"])
                esc = " ⚠ ESCALATED" if e["score"] >= alert_threshold else ""
                st.markdown(
                    f'<div class="feed-row" style="--fc:{fc}"><span class="t">{e["ts"][11:]}</span> '
                    f'<span class="s">[{e["status"]}]</span> {e["user"]} → {e["device"]} '
                    f'<span class="t">({e["action"]}, {e["score"]}){esc}</span></div>',
                    unsafe_allow_html=True,
                )
        else:
            st.caption("Awaiting telemetry…")

        st.markdown('<div class="panel-title">▌ TOP RISK ENTITIES</div>', unsafe_allow_html=True)
        if ss.events:
            best = {}
            for e in ss.events:
                best[e["user"]] = max(best.get(e["user"], 0), e["score"])
            top = pd.DataFrame(sorted(best.items(), key=lambda x: -x[1])[:6],
                               columns=["User", "Peak Risk"])
            st.dataframe(top, hide_index=True, use_container_width=True)

# ============================================================
# MODE: SHARED INFRASTRUCTURE
# ============================================================
elif active_mode == "Shared Infrastructure (Fraud Rings)":
    col_input, col_viz = st.columns([1, 1.4])

    with col_input:
        st.markdown('<div class="panel-title">▌ TELEMETRY INGESTION NODE</div>', unsafe_allow_html=True)
        with st.form("entity_form"):
            user_id = st.text_input("Target User ID", value="user_201")
            device_id = st.text_input("Hardware Device Fingerprint", value="device_MALICIOUS_1")
            ip_address = st.text_input("Source IP Address", value="10.0.0.99")
            action = st.selectbox("Telemetry Action Vector", list(ACTION_WEIGHT))
            submit = st.form_submit_button(">> EXECUTE GRAPH RISK EVALUATION")

        if submit:
            if not (user_id.strip() and device_id.strip() and ip_address.strip()):
                st.error("All entity fields are required.")
            else:
                u, d, i = user_id.strip(), device_id.strip(), ip_address.strip()
                assessment, source = None, "LOCAL-SIM"
                if backend_online:
                    data, error = api_post(
                        "/events/ingest",
                        {"user_id": u, "device_id": d, "ip_address": i, "action": action},
                    )
                    if error:
                        st.error(f"Backend ingestion failed: {error}")
                        st.caption("Falling back to local simulation for this event.")
                    else:
                        assessment, source = data.get("assessment", {}), "BACKEND"
                if assessment is None:
                    assessment = local_assess(u, d, i, action)

                score = assessment.get("entity_risk_score", 0)
                score = score if isinstance(score, (int, float)) else 0
                status = assessment.get("risk_status") or status_for(score)
                log_event(u, d, i, action, score, status, source)

                st.success(f">> TELEMETRY INGESTED  [{source}]")
                if score >= alert_threshold:
                    st.error(f"🚨 ESCALATION: score {score} breached threshold {alert_threshold}.")
                gauge(int(score), status)

                with st.expander("🔬 EXPLAINABILITY REASONING CHAIN", expanded=True):
                    chain = assessment.get("explainability_payload", {}).get("reasoning_chain", [])
                    if chain:
                        for r in chain:
                            st.warning(f"[!] {r}")
                    else:
                        st.info("No reasoning details were returned.")

    with col_viz:
        st.markdown('<div class="panel-title">▌ ENTITY NETWORK TOPOLOGY MAP</div>', unsafe_allow_html=True)
        nodes, edges = build_entity_graph()
        if not nodes:
            st.info("Graph is empty. Ingest telemetry or press **Load demo** to populate the topology.")
        else:
            render_graph(nodes, edges)
            st.markdown(
                '<span class="badge" style="color:#00ff66">● USER</span>'
                '<span class="badge" style="color:#ff0055">▲ SHARED DEVICE</span>'
                '<span class="badge" style="color:#ffb800">▲ DEVICE</span>'
                '<span class="badge" style="color:#00e5ff">■ IP</span>',
                unsafe_allow_html=True,
            )
        if clusters_now:
            st.markdown('<div class="panel-title">▌ DETECTED RINGS</div>', unsafe_allow_html=True)
            for dev, users in clusters_now.items():
                st.error(f"🕸️ Device `{dev}` ↔ {len(users)} accounts: {', '.join(users)}")

# ============================================================
# MODE: WASH-TRADING
# ============================================================
elif active_mode == "Circular Wash-Trading":
    st.markdown('<div class="panel-title">▌ DIRECTED TRANSACTION LEDGER & WASH-TRADING SURVEILLANCE</div>',
                unsafe_allow_html=True)
    col_tx, col_rep = st.columns([1, 1.2])

    with col_tx:
        with st.form("tx_form"):
            sender = st.text_input("Sender Account", value="trader_X")
            receiver = st.text_input("Receiver Account", value="trader_Y")
            amount = st.number_input("Transaction Volume ($ USD)", min_value=1.0, value=5000.0, step=100.0)
            timestamp = st.text_input("Timestamp", value=utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"))
            submit_tx = st.form_submit_button(">> INGEST TRANSACTION & SCAN LOOPS")

        if submit_tx:
            s, r = sender.strip(), receiver.strip()
            if not s or not r:
                st.error("Sender and receiver are required.")
            elif s == r:
                st.warning("Sender and receiver are the same account. Confirm this is intentional.")
            else:
                source, data = "LOCAL-SIM", None
                if backend_online:
                    data, error = api_post(
                        "/transactions/ingest",
                        {"sender": s, "receiver": r, "amount": amount, "timestamp": timestamp.strip()},
                    )
                    if error:
                        st.error(f"Backend ingestion failed: {error}")
                        st.caption("Recording locally instead.")
                        data = None
                    else:
                        source = "BACKEND"
                ss.txs.append({"ts": stamp(), "sender": s, "receiver": r,
                               "amount": float(amount), "source": source})

                flagged = bool(data.get("flagged_wash_trading")) if data else bool(find_cycles(ss.txs))
                if flagged:
                    st.error(f"🚨 ALERT: CLOSED-LOOP WASH TRADING DETECTED!  [{source}]")
                else:
                    st.success(f"Transaction recorded [{source}]. No wash-trading alert.")
                if data:
                    st.markdown("#### Backend Cycle Alerts")
                    st.json(data.get("active_cycle_alerts", []))

        if st.button("Fetch Backend Cycle Reports"):
            if not backend_online:
                st.error("Backend offline.")
            else:
                rep, error = api_get("/transactions/analysis/cycles")
                if error:
                    st.error(f"Error fetching reports: {error}")
                else:
                    st.metric("Total Active Rings (backend)", rep.get("total_active_cycles", 0))
                    st.json(rep.get("alerts", []))

    with col_rep:
        cycles = find_cycles(ss.txs)
        m1, m2, m3 = st.columns(3)
        m1.metric("Ledger Entries", len(ss.txs))
        m2.metric("Local Rings", len(cycles))
        m3.metric("Volume ($)", f"{sum(t['amount'] for t in ss.txs):,.0f}")

        if ss.txs:
            net = new_network("420px")
            net.set_options('{"edges":{"arrows":{"to":{"enabled":true}},"smooth":{"type":"curvedCW","roundness":0.2}}}')
            ring_nodes = {n for c in cycles for n in c}
            ring_edges = {(c[i], c[(i + 1) % len(c)]) for c in cycles for i in range(len(c))}
            agg = defaultdict(float)
            for t in ss.txs:
                agg[(t["sender"], t["receiver"])] += t["amount"]
                for n in (t["sender"], t["receiver"]):
                    net.add_node(n, label=n, shape="dot", size=22,
                                 color="#ff0055" if n in ring_nodes else "#00ff66")
            for (a, b), v in agg.items():
                hot = (a, b) in ring_edges
                net.add_edge(a, b, label=f"${v:,.0f}",
                             color="#ff0055" if hot else "#475569", width=3 if hot else 1.5)
            components.html(net.generate_html(), height=440, scrolling=True)
        else:
            st.info("Ledger is empty. Ingest a transaction or load the demo scenario.")

        if cycles:
            st.markdown('<div class="panel-title">▌ LOCALLY DETECTED CYCLES</div>', unsafe_allow_html=True)
            for c in cycles:
                st.error("🔁 " + " → ".join(c + [c[0]]))

# ============================================================
# MODE: THREAT HUNT CONSOLE
# ============================================================
elif active_mode == "Threat Hunt Console":
    st.markdown('<div class="panel-title">▌ THREAT HUNT CONSOLE // BLAST-RADIUS ANALYSIS</div>',
                unsafe_allow_html=True)
    nodes, edges = build_entity_graph()
    if not nodes:
        st.info("No graph data yet. Press **Load demo** in the sidebar or ingest telemetry first.")
    else:
        h1, h2 = st.columns([1, 1.6])
        with h1:
            pivot = st.selectbox("Pivot entity", sorted(nodes), help="Start hunting from this node.")
            hops = st.slider("Hop depth", 1, 4, 2)
            adj = neighbors_map(edges)
            reach = blast_radius(pivot, adj, hops)
            by_kind = defaultdict(list)
            for n, h in reach.items():
                if n != pivot:
                    by_kind[nodes[n]].append((n, h))

            k1, k2 = st.columns(2)
            k1.metric("Entities in radius", len(reach) - 1)
            k2.metric("Pivot type", nodes[pivot].upper())

            exposed_users = [n for n, _ in by_kind.get("user", [])]
            if exposed_users:
                st.warning(f"⚠ {len(exposed_users)} linked account(s) potentially exposed: "
                           f"{', '.join(sorted(exposed_users))}")
            for kind, items in by_kind.items():
                with st.expander(f"{kind.upper()} ({len(items)})", expanded=True):
                    st.dataframe(
                        pd.DataFrame(sorted(items, key=lambda x: x[1]), columns=["Entity", "Hops"]),
                        hide_index=True, use_container_width=True)
        with h2:
            render_graph(nodes, edges, highlight=reach, height="500px")

# ============================================================
# MODE: AUDIT LOG & EXPORT
# ============================================================
elif active_mode == "Audit Log & Export":
    st.markdown('<div class="panel-title">▌ IMMUTABLE-STYLE AUDIT TRAIL</div>', unsafe_allow_html=True)
    tab_e, tab_t = st.tabs(["TELEMETRY EVENTS", "TRANSACTIONS"])

    with tab_e:
        if ss.events:
            df = pd.DataFrame(ss.events)
            flt = st.multiselect("Filter by status", ["CRITICAL", "HIGH", "ELEVATED", "LOW"],
                                 default=["CRITICAL", "HIGH", "ELEVATED", "LOW"])
            view = df[df["status"].isin(flt)]
            st.dataframe(view, hide_index=True, use_container_width=True)
            st.download_button("⬇ EXPORT EVENTS (CSV)", view.to_csv(index=False).encode(),
                               "trustgraph_events.csv", "text/csv")
        else:
            st.info("No events recorded.")

    with tab_t:
        if ss.txs:
            dft = pd.DataFrame(ss.txs)
            st.dataframe(dft, hide_index=True, use_container_width=True)
            st.download_button("⬇ EXPORT TRANSACTIONS (CSV)", dft.to_csv(index=False).encode(),
                               "trustgraph_transactions.csv", "text/csv")
        else:
            st.info("No transactions recorded.")

# ============================================================
# MODE: EXECUTIVE INCIDENT BRIEF
# ============================================================
else:
    st.markdown('<div class="panel-title">▌ EXECUTIVE THREAT INTELLIGENCE REPORT</div>', unsafe_allow_html=True)

    if critical_cnt or cycles_now:
        level, lc = "ELEVATED — ACTIVE INDICATORS PRESENT", "#ff0055"
    elif total_events or ss.txs:
        level, lc = "GUARDED — NO CONFIRMED CLUSTERS", "#ffb800"
    else:
        level, lc = "NO DATA — AWAITING TELEMETRY", "#475569"

    cluster_html = "".join(
        f"<li><b>{d}</b> shared by {len(u)} accounts ({', '.join(u)})</li>" for d, u in clusters_now.items()
    ) or "<li>No shared-device clusters detected in this session.</li>"
    cycle_html = "".join(
        f"<li>{' → '.join(c + [c[0]])}</li>" for c in cycles_now
    ) or "<li>No circular transaction flows detected in this session.</li>"

    st.markdown(
        f"""
<div class="report-box">
  <h3>CONFIDENTIAL // SECURITY AUDIT BRIEFING</h3>
  <p><b>Generated:</b> {stamp()} UTC &nbsp;|&nbsp; <b>Target System:</b> TrustGraph Core Intelligence Engine v2.1</p>
  <p><b>Threat Posture:</b> <span style="color:{lc}; font-weight:bold">{level}</span></p>
  <hr>
  <p><b>1. Executive Summary</b><br>
  {total_events} telemetry events and {len(ss.txs)} transactions analysed this session.
  {critical_cnt} event(s) scored critical (≥ 75); {len(clusters_now)} shared-device cluster(s) and
  {len(cycles_now)} circular-flow ring(s) identified.</p>
  <p><b>2. Shared Hardware Clusters</b></p><ul>{cluster_html}</ul>
  <p><b>3. Circular Money Flows</b></p><ul>{cycle_html}</ul>
  <p><b>4. Recommended Defensive Actions</b></p>
  <ul>
    <li>Investigate shared-device relationships before taking enforcement action.</li>
    <li>Apply step-up identity verification where evidence supports it.</li>
    <li>Review flagged transaction cycles and apply appropriate controls.</li>
  </ul>
  <p><b>Important:</b> Findings reflect data ingested in this session
  ({'backend + local' if backend_online else 'local simulation'}). Validate against authoritative
  backend data before treating them as confirmed incidents.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    plain = io.StringIO()
    plain.write(f"TRUSTGRAPH EXECUTIVE BRIEF - {stamp()} UTC\n")
    plain.write(f"Posture: {level}\nEvents: {total_events} | Transactions: {len(ss.txs)} | Critical: {critical_cnt}\n\n")
    plain.write("SHARED-DEVICE CLUSTERS\n")
    for d, u in clusters_now.items():
        plain.write(f"- {d}: {', '.join(u)}\n")
    plain.write("\nCIRCULAR FLOWS\n")
    for c in cycles_now:
        plain.write("- " + " -> ".join(c + [c[0]]) + "\n")
    st.download_button("⬇ DOWNLOAD BRIEF (TXT)", plain.getvalue().encode(), "trustgraph_brief.txt", "text/plain")

st.markdown("---")
st.caption("TRUSTGRAPH // CYBER INTELLIGENCE COMMAND  |  Graph visualization and analytics dashboard  |  "
           "Demo data is simulated.")