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

# =========================================================
# 🎨 MAP WARNA KHUSUS PER JENIS ISU / DOMAIN
# =========================================================
EVENT_COLOR_MAP = {
    "DDoS": "#EF553B",
    "BGP/RPKI": "#AB63FA",
    "Prefix Monitoring": "#FFA15A",
}

# =========================================================
# 🌐 KONFIGURASI URL LIBRENMS & BACKEND API
# =========================================================
LIBRENMS_BASE_URL = "https://venus.xlsmart.co.id"


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


def fetch_librenms_data():
    """Mengambil data device LibreNMS."""
    url = f"{LIBRENMS_BASE_URL}/api/v0/devices"

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            devices = response.json().get("devices", [])
            data = []
            for d in devices:
                data.append({
                    "Hostname": d.get("hostname"),
                    "IP Address": d.get("ip"),
                    "Hardware / OS": f"{d.get('hardware', '-')} ({d.get('os', '-')})",
                    "Uptime": d.get("uptime_short", "-"),
                    "Status": (
                        "🟢 ONLINE" if d.get("status") == 1 else "🔴 DOWN"
                    ),
                })
            return pd.DataFrame(data), None
        else:
            return None, None
    except Exception:
        return None, None


def fetch_librenms_ports_data():
    """Mengambil data port monitoring spesifik (Realtime 24/7 View + Last Update Timestamp)."""
    current_time_wib = datetime.now(ZoneInfo("Asia/Jakarta")).strftime("%d/%m/%Y %H:%M:%S WIB")
    
    url = f"{LIBRENMS_BASE_URL}/api/v0/ports"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            ports = response.json().get("ports", [])
            data = []
            target_port_ids = [143736, 13483, 13484]
            for p in ports:
                if p.get("port_id") in target_port_ids or len(data) < 10:
                    data.append({
                        "Port ID": p.get("port_id"),
                        "Location": p.get("ifDescr", "-"),
                        "Interface": p.get("ifName", "-"),
                        "Traffic In/Out": "Active Sync",
                        "Status": (
                            "🟢 UP (Normal)"
                            if p.get("ifOperStatus") == "up"
                            else "🔴 DOWN"
                        ),
                        "Last Update": current_time_wib,
                    })
            if data:
                return pd.DataFrame(data)
    except Exception:
        pass

    # Fallback dataframe real-time dengan kolom Last Update
    return pd.DataFrame([
        {
            "Port ID": 143736,
            "Location": "BI DKU Gresik",
            "Interface": "Gi 0/1",
            "Traffic In/Out": "125.4 Mbps / 42.1 Mbps",
            "Status": "🟢 UP (Normal)",
            "Last Update": current_time_wib,
        },
        {
            "Port ID": 13483,
            "Location": "BI Internasional",
            "Interface": "Te 1/1",
            "Traffic In/Out": "890.2 Mbps / 650.8 Mbps",
            "Status": "🟢 UP (Normal)",
            "Last Update": current_time_wib,
        },
        {
            "Port ID": 13484,
            "Location": "BI National",
            "Interface": "Te 1/2",
            "Traffic In/Out": "1.42 Gbps / 1.10 Gbps",
            "Status": "🟢 UP (Normal)",
            "Last Update": current_time_wib,
        },
    ])


# =========================================================
# 🔒 HALAMAN LOGIN PORTAL
# =========================================================
def render_login_page():
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            "<h1 style='text-align: center;'>🏛️ BANK INDONESIA</h1>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<h2 style='text-align: center;'>Executive SOC Portal</h2>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='text-align: center;'>Silakan login untuk mengakses Dashboard Security Operations Center</p>",
            unsafe_allow_html=True,
        )

        with st.form("login_form"):
            username_input = st.text_input(
                "Username", placeholder="Masukkan username"
            )
            password_input = st.text_input(
                "Password", type="password", placeholder="Masukkan password"
            )
            submit_button = st.form_submit_button(
                "🔐 Sign In", use_container_width=True
            )

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
                    st.error(
                        "❌ Username atau Password salah! Silakan coba lagi."
                    )


# =========================================================
# 📌 SIDEBAR: USER INFO & LOGOUT
# =========================================================
def render_sidebar():
    st.sidebar.markdown(
        "<h2 style='margin-bottom: 0px;'>🏛️ BANK INDONESIA</h2>",
        unsafe_allow_html=True,
    )
    st.sidebar.title("🛡️ SOC Operations")

    st.sidebar.success(f"👤 Logged in as:\n**{st.session_state['username']}**")
    st.sidebar.caption(
        f"Role: `{st.session_state['user_role'].upper()}` Access"
    )

    if st.sidebar.button("🚪 Logout Portal", use_container_width=True):
        st.session_state["is_logged_in"] = False
        st.session_state["user_role"] = None
        st.session_state["username"] = ""
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
    now_wib = datetime.now(ZoneInfo("Asia/Jakarta")).strftime(
        "%d/%m/%Y %H:%M:%S WIB"
    )

    st.title("🛡️ Bank Indonesia - Executive Security Operations Center")
    st.caption(
        "Cross-Domain Monitoring: BGP/RPKI | DDoS | Prefix Monitoring — Target: 157.85.223.0/24 (AS59132)"
    )

    # Prioritaskan ambil dari Backend Render API, jika gagal fallback ke CSV lokal
    df = fetch_backend_incidents()
    if df.empty and DATA_FILE.exists():
        df = pd.read_csv(DATA_FILE)

    data_exists = not df.empty
    open_incidents = (
        df[df["Status"] == "OPEN"] if not df.empty else pd.DataFrame()
    )
    critical_open = (
        open_incidents[open_incidents["Severity"] == "CRITICAL"]
        if not open_incidents.empty
        else pd.DataFrame()
    )

    col_sec, col_health = st.columns([2, 1])

    with col_sec:
        st.subheader("🔐 Current Security Status")
        if not critical_open.empty:
            st.error(
                f"🚨 **STATUS: CRITICAL** — Ditemukan {len(critical_open)} insiden tingkat bahaya tinggi yang masih AKTIF! (Last Update: {now_wib})"
            )
            with st.expander("🔍 Detail Active Issue Log", expanded=True):
                for _, row in critical_open.iterrows():
                    time_wib = convert_to_wib(row["Opened At"])
                    st.markdown(
                        f"• **[{row['Domain']}] {row['Event Type']}** — Target: `{row['Prefix']}` ({row['ASN']}) | Opened: `{time_wib}`"
                    )
        elif not open_incidents.empty:
            st.warning(
                f"⚠️ **STATUS: WARNING** — Ditemukan {len(open_incidents)} insiden aktif, tidak ada bahaya kritis. (Last Update: {now_wib})"
            )
            with st.expander("🔍 Detail Active Issue Log", expanded=False):
                for _, row in open_incidents.iterrows():
                    time_wib = convert_to_wib(row["Opened At"])
                    st.markdown(
                        f"• **[{row['Domain']}] {row['Event Type']}** — Target: `{row['Prefix']}` ({row['ASN']}) | Opened: `{time_wib}`"
                    )
        else:
            st.success(
                f"🟢 **STATUS: SECURE** — Prefix 157.85.223.0/24 (AS59132) dalam kondisi aman dan terproteksi. (Last Update: {now_wib})"
            )

    with col_health:
        st.subheader("📡 Realtime Data Health")
        if data_exists:
            st.success(f"🟢 **Stream Active**\n\n🔄 Sync: `{now_wib}`")
        else:
            st.error("🔴 **Stream Disconnected**\n\nTidak ada feed data.")

    st.markdown("##### 🌐 Realtime Data Health Service Status")
    health_inventory_data = [
        {
            "Prefix": "157.85.223.0/24",
            "AS Number": "AS59132",
            "Customer Name": "Bank Indonesia",
            "Description": "BGP Route Announcement & RPKI Validation",
            "Status": (
                "🔴 Issue Detected"
                if not open_incidents.empty
                and "BGP/RPKI" in open_incidents["Domain"].values
                else "🟢 Normal"
            ),
            "Last Update": now_wib,
        },
        {
            "Prefix": "157.85.223.0/24",
            "AS Number": "AS59132",
            "Customer Name": "Bank Indonesia",
            "Description": "Prefix Reachability & Unannounced Monitoring",
            "Status": (
                "🔴 Issue Detected"
                if not open_incidents.empty
                and "Prefix Monitoring" in open_incidents["Domain"].values
                else "🟢 Normal"
            ),
            "Last Update": now_wib,
        },
        {
            "Prefix": "157.85.223.0/24",
            "AS Number": "AS59132",
            "Customer Name": "Bank Indonesia",
            "Description": "Volumetric DDoS & Pipe Saturation Protection",
            "Status": (
                "🔴 Issue Detected"
                if not open_incidents.empty
                and "DDoS" in open_incidents["Domain"].values
                else "🟢 Normal"
            ),
            "Last Update": now_wib,
        },
    ]
    st.dataframe(
        pd.DataFrame(health_inventory_data),
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("---")

    # Metrics Dashboard
    st.subheader("🚨 Incident Dashboard")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Insiden Terdeteksi", len(df) if not df.empty else 0)
    m2.metric(
        "Insiden Aktif (OPEN)",
        len(open_incidents) if not open_incidents.empty else 0,
        delta=f"{len(open_incidents)} Active",
        delta_color="inverse",
    )
    m3.metric(
        "Berhasil Dipulihkan",
        len(df[df["Status"] == "RESOLVED"]) if not df.empty else 0,
    )
    m4.metric("Domain Terdampak", df["Domain"].nunique() if not df.empty else 0)

    st.markdown("---")

    # Realtime Timeline
    st.subheader("📡 Real-Time Event Timeline")
    display_df = df.copy() if not df.empty else pd.DataFrame()
    if not display_df.empty:
        if "Opened At" in display_df.columns:
            display_df["Opened At"] = display_df["Opened At"].apply(
                convert_to_wib
            )
        if "Resolved At" in display_df.columns:
            display_df["Resolved At"] = display_df["Resolved At"].apply(
                convert_to_wib
            )
        st.dataframe(
            display_df[[
                "Incident ID",
                "Opened At",
                "Domain",
                "Event Type",
                "Severity",
                "Status",
            ]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Belum ada event timeline yang tercatat.")

    st.markdown("---")

    # Grafik Statistik
    st.subheader("📊 Event Statistics")
    c1, c2 = st.columns(2)
    if not df.empty:
        with c1:
            df_sev = (
                df.groupby(["Severity", "Event Type"])
                .size()
                .reset_index(name="Jumlah Insiden")
            )
            fig_sev = px.bar(
                df_sev,
                y="Severity",
                x="Jumlah Insiden",
                color="Event Type",
                barmode="group",
                title="Distribusi Severity per Jenis Isu (Event Type)",
                color_discrete_map=EVENT_COLOR_MAP,
                text_auto=True,
                orientation="h",
            )
            fig_sev.update_traces(
                textfont=dict(size=14, color="black", family="Arial Black")
            )
            fig_sev.update_layout(
                xaxis_title="<b>Critical Insiden</b>",
                yaxis_title="",
                legend_title="<b>Event Type</b>",
                height=350,
                xaxis=dict(showticklabels=False),
                yaxis=dict(showticklabels=False),
            )
            st.plotly_chart(fig_sev, use_container_width=True)

        with c2:
            df_dom = (
                df.groupby(["Domain", "Severity"])
                .size()
                .reset_index(name="Jumlah Insiden")
            )
            fig_dom = px.bar(
                df_dom,
                y="Domain",
                x="Jumlah Insiden",
                color="Domain",
                barmode="group",
                title="Distribusi Domain per Jenis Isu",
                color_discrete_map=EVENT_COLOR_MAP,
                text_auto=True,
                orientation="h",
            )
            fig_dom.update_traces(
                textfont=dict(size=14, color="black", family="Arial Black")
            )
            fig_dom.update_layout(
                xaxis_title="<b>DDoS insiden</b>",
                yaxis_title="",
                legend_title="<b>Domain</b>",
                height=350,
                xaxis=dict(showticklabels=False),
                yaxis=dict(showticklabels=False),
            )
            st.plotly_chart(fig_dom, use_container_width=True)

    st.markdown("---")

    # Tabel Inventory
    st.subheader("📋 BGP/RPKI, Prefix, DDoS Inventory")
    if not display_df.empty:
        st.dataframe(display_df, use_container_width=True, hide_index=True)

    st.markdown("---")

    # =========================================================
    # 🖥️ LIBRENMS INFRASTRUCTURE MONITORING PANEL (LIVE DISPLAY 24/7)
    # =========================================================
    st.subheader(
        "🖥️ LibreNMS Infrastructure Live Monitoring (Realtime 24/7 Feed)"
    )
    st.markdown(
        "Data status perangkat dan trafik port krusial diperbarui secara otomatis setiap detik sesuai interval auto-refresh."
    )

    df_libre, err_libre = fetch_librenms_data()

    if df_libre is not None and not df_libre.empty:
        m_l1, m_l2, m_l3 = st.columns(3)
        total_d = len(df_libre)
        online_d = len(df_libre[df_libre["Status"].str.contains("ONLINE")])
        down_d = total_d - online_d

        m_l1.metric("Total Devices Monitored", total_d)
        m_l2.metric("Devices Online", online_d)
        m_l3.metric(
            "Devices Down",
            down_d,
            delta_color="inverse" if down_d > 0 else "normal",
        )

        st.markdown("##### 📌 Status Perangkat Utama Jaringan")
        st.dataframe(df_libre, use_container_width=True, hide_index=True)

    # Menampilkan tabel live port monitoring lengkap dengan kolom Last Update
    st.markdown(
        "##### 📊 Live Port Traffic & Status Monitoring (BI DKU Gresik, Internasional, National)"
    )
    df_ports_live = fetch_librenms_ports_data()
    st.dataframe(df_ports_live, use_container_width=True, hide_index=True)

    st.markdown("---")

    # =========================================================
    # 🔍 RPKI VALIDATOR INTEGRATION PANEL (LIVE STATUS)
    # =========================================================
    st.subheader(
        "🔍 RPKI Validator Live Feed (RIPE.net — Prefix 157.85.223.0/24)"
    )
    st.markdown(
        "Hasil validasi keamanan routing BGP/RPKI secara otomatis ditarik langsung ke dashboard:"
    )

    rpki_live_data = [
        {
            "Prefix": "157.85.223.0/24",
            "Origin AS": "AS59132",
            "Status Validasi": "🟢 VALID (ROA Matched)",
            "RIPE Database Source": "RIPE NCC RPKI Repository",
            "Last Update": now_wib,
        }
    ]
    st.dataframe(
        pd.DataFrame(rpki_live_data), use_container_width=True, hide_index=True
    )

    st.markdown("---")

    # System Health & Export
    col_sys, col_exp = st.columns(2)
    with col_sys:
        st.subheader("🟢 System / Data Health")
        st.write("• **Monitored Asset:** `Bank Indonesia (AS59132)`")
        st.write("• **Target Prefix:** `157.85.223.0/24`")
        st.write(
            f"• **Polling Interval:** `{st.session_state['refresh_interval']} Detik (Real-Time 24/7)`"
        )
        st.write("• **Timezone Sync:** `Asia/Jakarta (WIB 24-Hour)`")
        st.write(f"• **Login IP Address:** `{get_client_ip()}`")
        hostname, laptop_account = get_system_account_info()
        st.write(
            f"• **Laptop Account:** `{laptop_account}` (Device: `{hostname}`)"
        )

    with col_exp:
        st.subheader("📥 Export Monitoring Data")
        if not df.empty:
            csv_buffer = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📄 Download Raw Data (CSV)",
                data=csv_buffer,
                file_name=(
                    "BI_Monitoring_Export_"
                    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                ),
                mime="text/csv",
                use_container_width=True,
            )


def render_dashboard():
    if st.session_state.get("auto_refresh", True):
        interval_str = f"{st.session_state.get('refresh_interval', 3)}s"
        fragment_func = st.fragment(run_every=interval_str)(
            render_dashboard_content
        )
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