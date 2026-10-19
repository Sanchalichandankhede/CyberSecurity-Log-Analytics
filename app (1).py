import subprocess
import pandas as pd
import streamlit as st
import plotly.express as px
from pathlib import Path

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

HDFS_COMMAND = r"C:\hadoop-3.2.4\bin\hdfs.cmd"

BASE_PATH = "/cybersecurity/results"

st.set_page_config(
    page_title="CyberShield | Security Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --------------------------------------------------
# CUSTOM CSS
# --------------------------------------------------

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b1120;
        color: #e5e7eb;
    }

    [data-testid="stSidebar"] {
        background-color: #111827;
    }

    [data-testid="stMetric"] {
        background-color: #172033;
        padding: 18px;
        border-radius: 12px;
        border: 1px solid #263449;
    }

    h1, h2, h3 {
        color: #60a5fa;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# --------------------------------------------------
# HDFS UTILITIES
# --------------------------------------------------

def run_hdfs_command(arguments):
    """Execute an HDFS command and return its output."""

    command = [HDFS_COMMAND] + arguments

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60,
        shell=False
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "HDFS command failed."
        )

    return result.stdout


def read_hdfs_csv(directory):
    """
    Read CSV part files from an HDFS output directory.
    Returns a Pandas DataFrame or None if unavailable.
    """

    try:
        listing = run_hdfs_command([
            "dfs", "-ls", directory
        ])

        files = []

        for line in listing.splitlines():
            parts = line.split()

            if not parts:
                continue

            path = parts[-1]

            if (
                "/part-" in path
                and path.lower().endswith(".csv")
            ):
                files.append(path)

        if not files:
            return None

        frames = []

        for file_path in files:
            csv_content = run_hdfs_command([
                "dfs", "-cat", file_path
            ])

            from io import StringIO

            frames.append(
                pd.read_csv(StringIO(csv_content))
            )

        if not frames:
            return None

        return pd.concat(
            frames,
            ignore_index=True
        )

    except Exception as error:
        st.warning(
            f"Could not read {directory}: {error}"
        )
        return None


# --------------------------------------------------
# LOAD ANALYTICS DATA
# --------------------------------------------------

@st.cache_data(ttl=60)
def load_dashboard_data():

    return {
        "traffic": read_hdfs_csv(
            f"{BASE_PATH}/traffic_summary_advanced"
        ),

        "ports": read_hdfs_csv(
            f"{BASE_PATH}/top_destination_ports"
        ),

        "attacks": read_hdfs_csv(
            f"{BASE_PATH}/attack_distribution"
        ),

        "statistics": read_hdfs_csv(
            f"{BASE_PATH}/traffic_statistics"
        ),

        "flags": read_hdfs_csv(
            f"{BASE_PATH}/flag_analysis"
        ),

        "original": read_hdfs_csv(
            f"{BASE_PATH}/traffic_summary"
        )
    }


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ CyberShield")
st.subheader("Cybersecurity Log Analytics Dashboard")

st.markdown(
    """
    Explore network traffic, inspect recorded attack labels,
    and investigate destination-port and packet-flow statistics.

    **Data source:** Hadoop HDFS + PySpark analytics
    """
)

st.divider()


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.title("Dashboard Controls")

if st.sidebar.button("🔄 Refresh Data"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.markdown("---")

st.sidebar.info(
    """
    **Analytics platform**

    - Hadoop HDFS
    - Apache Spark / PySpark
    - Pandas
    - Plotly
    - Streamlit
    """
)

data = load_dashboard_data()

traffic = data["traffic"]

if traffic is None:
    traffic = data["original"]

attacks = data["attacks"]
ports = data["ports"]
statistics = data["statistics"]
flags = data["flags"]


# --------------------------------------------------
# SUMMARY METRICS
# --------------------------------------------------

st.header("Network Overview")

if traffic is not None and {
    "TrafficType", "count"
}.issubset(traffic.columns):

    counts = dict(
        zip(
            traffic["TrafficType"].astype(str),
            pd.to_numeric(
                traffic["count"],
                errors="coerce"
            ).fillna(0)
        )
    )

    benign_count = int(counts.get("Benign", 0))

    suspicious_count = int(
        counts.get("Potentially Malicious", 0)
    )

    total_flows = benign_count + suspicious_count

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Recorded Flows",
        f"{total_flows:,}"
    )

    col2.metric(
        "Benign-Labeled Flows",
        f"{benign_count:,}"
    )

    col3.metric(
        "Potentially Malicious-Labeled Flows",
        f"{suspicious_count:,}"
    )

    st.caption(
        "Potentially malicious means the dataset label is not "
        "BENIGN. It does not independently establish that a "
        "flow is malicious."
    )

elif attacks is not None and {
    "Label", "count"
}.issubset(attacks.columns):

    total_flows = int(
        pd.to_numeric(
            attacks["count"],
            errors="coerce"
        ).fillna(0).sum()
    )

    col1, col2 = st.columns(2)

    col1.metric(
        "Total Recorded Flows",
        f"{total_flows:,}"
    )

    col2.metric(
        "Recorded Labels",
        f"{attacks['Label'].nunique():,}"
    )

else:

    st.warning(
        "Traffic summary is unavailable. "
        "Check the HDFS results directory."
    )


st.divider()


# --------------------------------------------------
# ATTACK DISTRIBUTION
# --------------------------------------------------

st.header("1. Attack Label Distribution")

if attacks is not None and {
    "Label", "count"
}.issubset(attacks.columns):

    attacks = attacks.copy()

    attacks["count"] = pd.to_numeric(
        attacks["count"],
        errors="coerce"
    )

    attacks = attacks.dropna(
        subset=["Label", "count"]
    )

    col1, col2 = st.columns(2)

    with col1:

        fig = px.bar(
            attacks.sort_values(
                "count",
                ascending=False
            ),
            x="Label",
            y="count",
            title="Recorded Flows by Label",
            labels={
                "Label": "Dataset Label",
                "count": "Number of Flows"
            },
            template="plotly_dark"
        )

        fig.update_layout(
            xaxis_tickangle=-35
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with col2:

        fig = px.pie(
            attacks,
            names="Label",
            values="count",
            title="Traffic Label Composition",
            template="plotly_dark"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with st.expander("View attack distribution data"):

        st.dataframe(
            attacks,
            use_container_width=True
        )

else:

    st.info(
        "Attack distribution is unavailable. "
        "Run advanced_analytics.py to generate it."
    )


st.divider()


# --------------------------------------------------
# DESTINATION PORT ANALYSIS
# --------------------------------------------------

st.header("2. Destination Port Analysis")

if ports is not None and {
    "Destination Port", "count"
}.issubset(ports.columns):

    ports = ports.copy()

    ports["Destination Port"] = pd.to_numeric(
        ports["Destination Port"],
        errors="coerce"
    )

    ports["count"] = pd.to_numeric(
        ports["count"],
        errors="coerce"
    )

    ports = ports.dropna(
        subset=["Destination Port", "count"]
    )

    ports["Destination Port"] = (
        ports["Destination Port"].astype(int).astype(str)
    )

    fig = px.bar(
        ports.sort_values(
            "count",
            ascending=True
        ),
        x="count",
        y="Destination Port",
        orientation="h",
        title="Most Frequently Observed Destination Ports",
        labels={
            "Destination Port": "Destination Port",
            "count": "Number of Flows"
        },
        template="plotly_dark"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    with st.expander("View destination port data"):

        st.dataframe(
            ports,
            use_container_width=True
        )

else:

    st.info(
        "Destination-port data is unavailable. "
        "Run advanced_analytics.py first."
    )


st.divider()


# --------------------------------------------------
# FLOW STATISTICS
# --------------------------------------------------

st.header("3. Network Traffic Statistics")

if statistics is not None and "Label" in statistics.columns:

    numeric_columns = [
        column
        for column in [
            "FlowCount",
            "AverageFlowDuration",
            "AverageForwardPackets",
            "AverageBackwardPackets"
        ]
        if column in statistics.columns
    ]

    if numeric_columns:

        for column in numeric_columns:
            statistics[column] = pd.to_numeric(
                statistics[column],
                errors="coerce"
            )

        selected_metric = st.selectbox(
            "Select a metric",
            numeric_columns,
            format_func=lambda value: value.replace(
                "Average", ""
            ).replace("Flow", " Flow ").strip()
        )

        fig = px.bar(
            statistics.sort_values(
                selected_metric,
                ascending=False
            ),
            x="Label",
            y=selected_metric,
            title=f"{selected_metric} by Traffic Label",
            labels={
                "Label": "Dataset Label",
                selected_metric: selected_metric
            },
            template="plotly_dark"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with st.expander("View network statistics"):

        st.dataframe(
            statistics,
            use_container_width=True
        )

else:

    st.info(
        "Traffic statistics are unavailable. "
        "Run advanced_analytics.py first."
    )


st.divider()


# --------------------------------------------------
# TCP FLAG ANALYSIS
# --------------------------------------------------

st.header("4. TCP Flag Analysis")

if flags is not None and "Label" in flags.columns:

    numeric_flags = [
        column
        for column in [
            "AverageSYNFlagCount",
            "AverageRSTFlagCount"
        ]
        if column in flags.columns
    ]

    if numeric_flags:

        for column in numeric_flags:
            flags[column] = pd.to_numeric(
                flags[column],
                errors="coerce"
            )

        flag_metric = st.selectbox(
            "Select TCP flag metric",
            numeric_flags,
            key="flag_metric"
        )

        fig = px.bar(
            flags.sort_values(
                flag_metric,
                ascending=False
            ),
            x="Label",
            y=flag_metric,
            title=f"{flag_metric} by Traffic Label",
            template="plotly_dark"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with st.expander("View TCP flag statistics"):

        st.dataframe(
            flags,
            use_container_width=True
        )

else:

    st.info(
        "TCP flag statistics are unavailable. "
        "Run advanced_analytics.py first."
    )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "CyberShield | Built with Hadoop, PySpark, "
    "Pandas, Plotly and Streamlit"
)