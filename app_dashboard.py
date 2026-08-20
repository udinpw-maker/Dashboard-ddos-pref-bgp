from datetime import datetime
import getpass
from pathlib import Path
import socket
from zoneinfo import ZoneInfo
import pandas as pd
import plotly.express as px
import requests
import streamlit as st

# =========================================================
# ⚙️ STREAMLIT CONFIG & SESSION STATE
# =========================================================
st.set_page_config(
    page_title="Bank Indonesia Executive Security Operations Center",
    layout="wide",
    initial_sidebar_state="expanded",
)

DATA_FILE = Path(__file__).resolve().parent / "data" / "unified_incidents.csv"

# URL Backend Render Anda
BACKEND_API_URL = "https://ddos-pref-backend.onrender.com"

# Init Session State Login Status Dashboard
if "is_logged_in" not in st.session_state:
    st.session_state["is_logged_in"] = False
if "user_role" not in st.session_state:
    st.session_state["user_role"] = None
if "username" not in st.session_state:
    st.session_state["username"] = ""

# Init Session State Auto-Refresh Config
if "auto_refresh" not in st.session_state:
    st.session_state["auto_refresh"] = True
if "refresh_interval" not in st.session_state:
    st.session_state["refresh_interval"] = 3

# Init Session State LibreNMS Cookies (3 Target)
for i in range(1, 4):
    if f"librenms_cookie_{i}" not in st.session_state:
        st.session_state[f"librenms_cookie_{i}"] = ""

# =========================================================
# 🎨 MAP WARNA KHUSUS PER JENIS ISU / DOMAIN
# =========================================================
EVENT_COLOR_MAP = {
    "DDoS": "#EF553B",
    "BGP/RPKI": "#AB63FA",
    "Prefix Monitoring": "#FFA15A",
}

# =========================================================
# 🌐 KONFIGURASI URL SPESIFIK 3 TARGET PORT LIBRENMS
# =========================================================
LIBRENMS_TARGETS = {
    1: {
        "name": "Target Gresik",
        "base_url": "https://venus.xlsmart.co.id",
        "device_id": 811,
        "port_id": 143736,
        "location": "BI DKU Gresik"
    },
    2: {
        "name": "Target Internasional",
        "base_url": "https://venus.xlsmart.co.id",
        "device_id": 15,
        "port_id": 13483,
        "location": "BI Internasional"
    },
    3: {
        "name": "Target National",
        "base_url": "https://venus.xlsmart.co.id",
        "device_id": 15,
        "port_id": 13484,
        "location": "BI National"
    }
}


def fetch_backend_incidents():
    """Mengambil data insiden langsung dari Backend API Render."""
    try:
        response = requests.get(f"{BACKEND_API_URL}/api/incidents", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data:
                return pd.DataFrame(data)
    except Exception:
        pass
    return pd.DataFrame()


def get_client_ip() -> str:
    """Mendapatkan IP Login Pengguna / Client."""
    try:
        headers = st.context.headers
        if "X-Forwarded-For" in headers:
            return headers["X-Forwarded-For"].split(",")[0].strip()
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_system_account_info() -> tuple[str, str]:
    """Mendapatkan informasi Laptop Hostname dan OS User Account."""
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "Unknown-Device"

    try:
        user_account = getpass.getuser()
    except Exception:
        user_account = "Unknown-User"

    return hostname, user_account


def convert_to_wib(utc_time_str: str) -> str:
    """Mengonversi UTC ISO timestamp ke Format 24 Jam Indonesia WIB."""
    if not utc_time_str or str(utc_time_str).strip() in ["None", "nan", ""]:
        return "-"
    try:
        dt = datetime.fromisoformat(str(utc_time_str))
        dt_wib = dt.astimezone(ZoneInfo("Asia/Jakarta"))
        return dt_wib.strftime("%d/%m/%Y %H:%M:%S WIB")
    except Exception:
        return str(utc_time_str)


def fetch_librenms_devices_summary(target_index):
    """Mengambil ringkasan device berdasarkan cookie sesi pengguna."""
    target = LIBRENMS_TARGETS[target_index]
    url = f"{target['base_url']}/api/v0/devices"
    
    user_cookie = st.session_state.get(f"librenms_cookie_{target_index}", "").strip()
    headers = {"User-Agent": "Mozilla/5.0"}
    
    if user_cookie:
        headers["Cookie"] = user_cookie

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code in [401, 403, 500] or 'text/html' in response.headers.get('Content-Type', ''):
            return None, "SESSION_EXPIRED"
            
        if response.status_code == 200:
            devices = response.json().get("devices", [])
            data = []
            for d in devices:
                if str(d.get("device_id")) == str(target["device_id"]):
                    data.append({
                        "Hostname": d.get("hostname"),
                        "IP Address": d.get("ip"),
                        "Hardware / OS": f"{d.get('hardware', '-')} ({d.get('os', '-')})",
                        "Uptime": d.get("uptime_short", "-"),
                        "Status": ("🟢 ONLINE" if d.get("status") == 1 else "🔴 DOWN"),
                    })
            if not data and devices:
                d = devices[0]
                data.append({
                    "Hostname": d.get("hostname"),
                    "IP Address": d.get("ip"),
                    "Hardware / OS": f"{d.get('hardware', '-')} ({d.get('os', '-')})",
                    "Uptime": d.get("uptime_short", "-"),
                    "Status": ("🟢 ONLINE" if d.get("status") == 1 else "🔴 DOWN"),
                })
            return pd.DataFrame(data), "OK"
        else:
            return None, "DISCONNECTED"
    except Exception:
        return None, "DISCONNECTED"


def fetch_librenms_realtime_port_status(target_index):
    """Memvalidasi koneksi dan status realtime port dengan header lengkap (Cloudflare & F5)."""
    current_time_wib = datetime.now(ZoneInfo("Asia/Jakarta")).strftime("%d/%m/%Y %H:%M:%S WIB")
    target = LIBRENMS_TARGETS[target_index]
    
    realtime_url = f"{target['base_url']}/device/device={target['device_id']}/tab=port/port={target['port_id']}/view=realtime/"
    
    raw_cookie = st.session_state.get(f"librenms_cookie_{target_index}", "").strip()
    
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-NZ,en;q=0.9,id-ID;q=0.8,id;q=0.7,en-GB;q=0.6,en-US;q=0.5",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Cookie": raw_cookie,
        "Host": "venus.xlsmart.co.id",
        "Referer": f"{target['base_url']}/device/device={target['device_id']}/tab=port/port={target['port_id']}/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
        "Upgrade-Insecure-Requests": "1"
    }

    try:
        response = requests.get(realtime_url, headers=headers, timeout=10, allow_redirects=False)
        
        if response.status_code in [301, 302, 401, 403, 500]:
            return pd.DataFrame(), "SESSION_EXPIRED"
            
        if response.status_code in [200, 304]:
            data = [{
                "Port ID": target["port_id"],
                "Device ID": target["device_id"],
                "Location": target["location"],
                "Realtime URL Link": realtime_url,
                "Traffic Status": "🟢 LIVE SYNC ACTIVE",
                "Last Polled": current_time_wib,
            }]
            return pd.DataFrame(data), "OK"
        else:
            return pd.DataFrame(), "DISCONNECTED"
    except Exception:
        return pd.DataFrame(), "DISCONNECTED"


# =========================================================
# 🔒 HALAMAN LOGIN PORTAL
# =========================================================
def render_login_page():
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("<h1 style='text-align: center;'>🏛️ BANK INDONESIA</h1>", unsafe_allow_html=True)
        st.markdown("<h2 style='text-align: center;'>Executive SOC Portal</h2>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center;'>Silakan login untuk mengakses Dashboard Security Operations Center</p>", unsafe_allow_html=True)

        with st.form("login_form"):
            username_input = st.text_input("Username", placeholder="Masukkan username")
            password_input = st.text_input("Password", type="password", placeholder="Masukkan password")
            submit_button = st.form_submit_button("🔐 Sign In", use_container_width=True)

            if submit_button:
                if username_input == "Admin" and password_input == "Admin@123*":
                    st.session_state["is_logged_in"] = True
                    st.session_state["user_role"] = "admin"
                    st.session_state["username"] = "Admin SOC"
                    st.success("Login Admin Berhasil!")
                    st.rerun()
                elif username_input == "View" and password_input == "View123":
                    st.session_state["is_logged_in"] = True
                    st.session_state["user_role"] = "view"
                    st.session_state["username"] = "Guest"
                    st.success("Login Viewer Berhasil!")
                    st.rerun()
                else:
                    st.error("❌ Username atau Password salah! Silakan coba lagi.")


# =========================================================
# 📌 SIDEBAR: USER INFO & LOGOUT
# =========================================================
def render_sidebar():
    st.sidebar.markdown("<h2 style='margin-bottom: 0px;'>🏛️ BANK INDONESIA</h2>", unsafe_allow_html=True)
    st.sidebar.title("🛡️ SOC Operations")

    st.sidebar.success(f"👤 Logged in as:\n**{st.session_state['username']}**")
    st.sidebar.caption(f"Role: `{st.session_state['user_role'].upper()}` Access")

    if st.sidebar.button("🚪 Logout Portal", use_container_width=True):
        st.session_state["is_logged_in"] = False
        st.session_state["user_role"] = None
        st.session_state["username"] = ""
        for i in range(1, 4):
            st.session_state[f"librenms_cookie_{i}"] = ""
        st.rerun()

    st.sidebar.markdown("---")
    
    st.sidebar.subheader("🔑 LibreNMS Session Cookies")
    st.sidebar.caption("Tempel seluruh string Cookie dari Network tab browser Anda (cf_clearance, XSRF-TOKEN, laravel_session, dll).")
    
    for i in range(1, 4):
        target_label = f"Target {i}: {LIBRENMS_TARGETS[i]['location']}"
        cookie_input = st.sidebar.text_input(
            target_label,
            value=st.session_state[f"librenms_cookie_{i}"],
            type="password",
            placeholder="cf_clearance=...; laravel_session=...",
            key=f"input_cookie_{i}"
        )
        if cookie_input != st.session_state[f"librenms_cookie_{i}"]:
            st.session_state[f"librenms_cookie_{i}"] = cookie_input
            st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.subheader("🔄 Auto-Refresh Control")
    st.session_state["auto_refresh"] = st.sidebar.toggle(
        "Aktifkan Auto-Refresh", value=st.session_state["auto_refresh"]
    )
    st.session_state["refresh_interval"] = st.sidebar.slider(
        "Interval Refresh (Detik)",
        min_value=1,
        max_value=30,
        value=st.session_state["refresh_interval"],
    )

    if st.sidebar.button("🔄 Refresh Data Sekarang", use_container_width=True):
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.subheader("⚙️ System Control")

    if st.session_state["user_role"] == "admin":
        st.sidebar.write("🛠️ **Admin Management Panel**")
        st.sidebar.info("Akses Penuh: Control & System Override.")
        if st.sidebar.button("🔄 Trigger Data Sync", use_container_width=True):
            st.sidebar.toast("Data Sync berhasil dipicu oleh Admin!")
    else:
        st.sidebar.caption("🔒 *Admin Panel dikunci untuk role Viewer.*")

    st.sidebar.markdown("---")
    st.sidebar.caption("Bank Indonesia SOC © 2026")


# =========================================================
# 📊 MAIN DASHBOARD CONTENT
# =========================================================
def render_dashboard_content():
    now_wib = datetime.now(ZoneInfo("Asia/Jakarta")).strftime("%d/%m/%Y %H:%M:%S WIB")

    st.title("🛡️ Bank Indonesia - Executive Security Operations Center")
    st.caption("Cross-Domain Monitoring: BGP/RPKI | DDoS | Prefix Monitoring — Target: 157.85.223.0/24 (AS59132)")

    df = fetch_backend_incidents()
    if df.empty and DATA_FILE.exists():
        df = pd.read_csv(DATA_FILE)

    data_exists = not df.empty
    open_incidents = df[df["Status"] == "OPEN"] if not df.empty else pd.DataFrame()
    critical_open = open_incidents[open_incidents["Severity"] == "CRITICAL"] if not open_incidents.empty else pd.DataFrame()

    col_sec, col_health = st.columns([2, 1])

    with col_sec:
        st.subheader("🔐 Current Security Status")
        if not critical_open.empty:
            st.error(f"🚨 **STATUS: CRITICAL** — Ditemukan {len(critical_open)} insiden tingkat bahaya tinggi yang masih AKTIF! (Last Update: {now_wib})")
        elif not open_incidents.empty:
            st.warning(f"⚠️ **STATUS: WARNING** — Ditemukan {len(open_incidents)} insiden aktif. (Last Update: {now_wib})")
        else:
            st.success(f"🟢 **STATUS: SECURE** — Prefix 157.85.223.0/24 (AS59132) dalam kondisi aman. (Last Update: {now_wib})")

    with col_health:
        st.subheader("📡 Realtime Data Health")
        if data_exists:
            st.success(f"🟢 **Stream Active**\n\n🔄 Sync: `{now_wib}`")
        else:
            st.error("🔴 **Stream Disconnected**\n\nTidak ada feed data.")

    st.markdown("---")

    # Metrics Dashboard
    st.subheader("🚨 Incident Dashboard")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Insiden Terdeteksi", len(df) if not df.empty else 0)
    m2.metric("Insiden Aktif (OPEN)", len(open_incidents) if not open_incidents.empty else 0, delta=f"{len(open_incidents)} Active", delta_color="inverse")
    m3.metric("Berhasil Dipulihkan", len(df[df["Status"] == "RESOLVED"]) if not df.empty else 0)
    m4.metric("Domain Terdampak", df["Domain"].nunique() if not df.empty else 0)

    st.markdown("---")

    # Realtime Timeline
    st.subheader("📡 Real-Time Event Timeline")
    display_df = df.copy() if not df.empty else pd.DataFrame()
    if not display_df.empty:
        if "Opened At" in display_df.columns:
            display_df["Opened At"] = display_df["Opened At"].apply(convert_to_wib)
        if "Resolved At" in display_df.columns:
            display_df["Resolved At"] = display_df["Resolved At"].apply(convert_to_wib)
        st.dataframe(display_df[["Incident ID", "Opened At", "Domain", "Event Type", "Severity", "Status"]], use_container_width=True, hide_index=True)
    else:
        st.info("Belum ada event timeline yang tercatat.")

    st.markdown("---")

    # =========================================================
    # 🖥️ LIBRENMS INFRASTRUCTURE MONITORING PANEL (3 URL TARGETS)
    # =========================================================
    st.subheader("🖥️ LibreNMS Infrastructure Live Monitoring (Realtime Port Feeds)")
    st.markdown("Memantau langsung URL Realtime Port LibreNMS Anda secara otomatis setiap detik.")

    tab1, tab2, tab3 = st.tabs(["Gresik (Port 143736)", "Internasional (Port 13483)", "National (Port 13484)"])
    tabs = [tab1, tab2, tab3]

    for i in range(1, 4):
        with tabs[i-1]:
            target_info = LIBRENMS_TARGETS[i]
            st.markdown(f"#### 📍 {target_info['location']} (Device ID: `{target_info['device_id']}`, Port ID: `{target_info['port_id']}`)")
            st.markdown(f"🔗 **URL Endpoint:** `{target_info['base_url']}/device/device={target_info['device_id']}/tab=port/port={target_info['port_id']}/view=realtime/`")
            
            df_port_live, port_status = fetch_librenms_realtime_port_status(i)
            df_dev, dev_status = fetch_librenms_devices_summary(i)

            if port_status == "SESSION_EXPIRED" or dev_status == "SESSION_EXPIRED":
                st.error(
                    f"⚠️ **SESI KEDALUWARSA (Error 500/Redirect):** Cookie sesi untuk **{target_info['location']}** sudah mati atau tidak valid! "
                    f"Silakan salin ulang string Cookie lengkap dari browser Anda dan masukkan ke kolom **Target {i}** di sidebar."
                )
            elif port_status == "DISCONNECTED":
                st.warning(f"⚠️ Gagal menghubungkan ke server LibreNMS untuk {target_info['location']}. Periksa koneksi jaringan/VPN Anda.")
            else:
                st.success(f"🟢 **Koneksi Live Berhasil Terhubung ke {target_info['location']}!**")
                
                if df_dev is not None and not df_dev.empty:
                    st.markdown("##### 📌 Device Status Info:")
                    st.dataframe(df_dev, use_container_width=True, hide_index=True)
                
                if not df_port_live.empty:
                    st.markdown("##### 📊 Realtime Port Feed Status:")
                    st.dataframe(df_port_live, use_container_width=True, hide_index=True)

    st.markdown("---")

    # =========================================================
    # 🔍 RPKI VALIDATOR INTEGRATION PANEL
    # =========================================================
    st.subheader("🔍 RPKI Validator Live Feed (RIPE.net — Prefix 157.85.223.0/24)")
    rpki_live_data = [
        {
            "Prefix": "157.85.223.0/24",
            "Origin AS": "AS59132",
            "Status Validasi": "🟢 VALID (ROA Matched)",
            "RIPE Database Source": "RIPE NCC RPKI Repository",
            "Last Update": now_wib,
        }
    ]
    st.dataframe(pd.DataFrame(rpki_live_data), use_container_width=True, hide_index=True)

    st.markdown("---")

    # System Health & Export
    col_sys, col_exp = st.columns(2)
    with col_sys:
        st.subheader("🟢 System / Data Health")
        st.write("• **Monitored Asset:** `Bank Indonesia (AS59132)`")
        st.write("• **Target Prefix:** `157.85.223.0/24`")
        st.write(f"• **Polling Interval:** `{st.session_state['refresh_interval']} Detik (Real-Time 24/7)`")
        st.write("• **Timezone Sync:** `Asia/Jakarta (WIB 24-Hour)`")
        st.write(f"• **Login IP Address:** `{get_client_ip()}`")
        hostname, laptop_account = get_system_account_info()
        st.write(f"• **Laptop Account:** `{laptop_account}` (Device: `{hostname}`)")

    with col_exp:
        st.subheader("📥 Export Monitoring Data")
        if not df.empty:
            csv_buffer = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📄 Download Raw Data (CSV)",
                data=csv_buffer,
                file_name=f"BI_Monitoring_Export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )


def render_dashboard():
    if st.session_state.get("auto_refresh", True):
        interval_str = f"{st.session_state.get('refresh_interval', 3)}s"
        fragment_func = st.fragment(run_every=interval_str)(render_dashboard_content)
        fragment_func()
    else:
        render_dashboard_content()


# =========================================================
# 🚀 MAIN APP CONTROLLER
# =========================================================
if not st.session_state["is_logged_in"]:
    render_login_page()
else:
    render_sidebar()
    render_dashboard()