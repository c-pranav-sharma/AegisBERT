import streamlit as st
import requests
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="Zero-Day Agent", page_icon="🛡️", layout="wide")

# Custom CSS for a professional look
st.markdown("""
    <style>
    .stMetric { background-color: #1e2130; padding: 15px; border-radius: 10px; border: 1px solid #3e4255; }
    [data-testid="stMetricValue"] { color: #00e676; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Zero-Day Threat Intel Engine")
st.caption("ModernBERT Multi-Class Vulnerability Classifier")
st.markdown("---")

API_URL = "http://api:8000/analyze"

desc = st.text_area("Vulnerability Description / Logs / Code:", placeholder="Paste technical data here...", height=300)

if st.button("Run Forensic Analysis", use_container_width=True):
    if desc:
        with st.spinner("Analyzing threat vectors..."):
            try:
                response = requests.post(API_URL, json={"cve_description": desc})
                
                if response.status_code == 200:
                    result = response.json()
                    st.success("Analysis Complete!")
                    
                    # 1. Top Level Metrics
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Detected Type", result['prediction'])
                    with col2:
                        st.metric("Risk Level", result['risk_level'])
                    with col3:
                        st.metric("Confidence", result['confidence'])

                    # 2. Probability Graph Logic
                    scores = result['scores']
                    
                    # Convert API scores to a DataFrame for Plotly
                    plot_data = []
                    for label, value in scores.items():
                        # Convert "99.15%" string to float 99.15
                        num_val = float(value.replace('%', ''))
                        plot_data.append({"Attack Type": label, "Probability (%)": num_val})
                    
                    df = pd.DataFrame(plot_data).sort_values(by="Probability (%)", ascending=True)

                    # 3. Dynamic Color Mapping
                    color_map = {
                        "Remote Code Execution (RCE)": "#ff4b4b",
                        "Command Injection": "#ff4b4b",
                        "Buffer Overflow (B_OVERFLOW)": "#ff4b4b",
                        "SQL Injection (SQLI)": "#ffa500",
                        "SSRF": "#ffa500",
                        "Privilege Escalation (PRIV_ESC)": "#ffa500"
                    }

                    fig = px.bar(
                        df, x='Probability (%)', y='Attack Type',
                        orientation='h', text='Probability (%)',
                        color='Attack Type', color_discrete_map=color_map,
                        template="plotly_dark"
                    )
                    
                    fig.update_layout(xaxis=dict(range=[0, 110]), showlegend=False, height=500)
                    st.plotly_chart(fig, use_container_width=True)
                    
                else:
                    st.error(f"API Error: {response.status_code}")
            except Exception as e:
                # This catches the 'Confidence' KeyError if the API and UI don't match
                st.error(f"UI Processing Error: {str(e)}")
    else:
        st.warning("Please enter data to analyze.")