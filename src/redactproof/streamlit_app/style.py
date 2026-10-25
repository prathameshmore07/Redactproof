import streamlit as st

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

/* Global app typography & background */
html, body, [class*="css"] {
    font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
}

code, pre, .stCodeBlock {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Glassmorphism Card Style */
.glass-panel {
    background: rgba(15, 23, 42, 0.75);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 20px 24px;
    margin-bottom: 20px;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 0 1px 1px rgba(255, 255, 255, 0.05);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.glass-panel:hover {
    border-color: rgba(99, 102, 241, 0.3);
    box-shadow: 0 15px 35px -5px rgba(0, 0, 0, 0.6), 0 0 15px rgba(99, 102, 241, 0.15);
}

/* Metric / Stat Card */
.stat-card {
    background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.9) 100%);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 14px;
    padding: 16px 20px;
    text-align: left;
    position: relative;
    overflow: hidden;
}

.stat-card::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    width: 4px;
    height: 100%;
    background: linear-gradient(180deg, #06b6d4, #6366f1);
}

.stat-value {
    font-size: 28px;
    font-weight: 800;
    color: #f8fafc;
    letter-spacing: -0.5px;
    margin-bottom: 4px;
}

.stat-label {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: #94a3b8;
}

/* Glowing Badges */
.badge-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
}

.badge-critical {
    background: rgba(239, 68, 68, 0.18);
    color: #fca5a5;
    border: 1px solid rgba(239, 68, 68, 0.4);
    box-shadow: 0 0 10px rgba(239, 68, 68, 0.2);
}

.badge-high {
    background: rgba(249, 115, 22, 0.18);
    color: #fdba74;
    border: 1px solid rgba(249, 115, 22, 0.4);
    box-shadow: 0 0 10px rgba(249, 115, 22, 0.2);
}

.badge-medium {
    background: rgba(234, 179, 8, 0.18);
    color: #fde047;
    border: 1px solid rgba(234, 179, 8, 0.4);
}

.badge-low {
    background: rgba(148, 163, 184, 0.18);
    color: #cbd5e1;
    border: 1px solid rgba(148, 163, 184, 0.3);
}

.badge-pass {
    background: rgba(16, 185, 129, 0.18);
    color: #6ee7b7;
    border: 1px solid rgba(16, 185, 129, 0.4);
    box-shadow: 0 0 10px rgba(16, 185, 129, 0.2);
}

/* Hero Title Header */
.hero-header {
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.hero-title {
    font-size: 32px;
    font-weight: 800;
    background: linear-gradient(135deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -0.5px;
    display: flex;
    align-items: center;
    gap: 12px;
}

.hero-subtitle {
    font-size: 14px;
    color: #94a3b8;
    margin-top: 6px;
    line-height: 1.5;
}

/* Custom styled buttons */
div.stButton > button {
    border-radius: 10px;
    font-weight: 600;
    font-size: 13px;
    letter-spacing: 0.3px;
    transition: all 0.2s ease;
}

div.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 14px rgba(6, 182, 212, 0.35);
}

/* Primary CTA Button */
div.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #0284c7 0%, #4f46e5 100%);
    border: none;
    color: white;
}

/* Custom animated pulse indicator */
@keyframes pulseGlow {
    0% { transform: scale(0.95); opacity: 0.8; }
    50% { transform: scale(1.05); opacity: 1; }
    100% { transform: scale(0.95); opacity: 0.8; }
}

.pulse-indicator {
    animation: pulseGlow 2s infinite ease-in-out;
}
</style>
"""

def inject_styles():
    """Injects the custom design system CSS into the Streamlit session."""
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
