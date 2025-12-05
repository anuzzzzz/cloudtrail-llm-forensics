#!/usr/bin/env python3
"""Streamlit frontend for LLM forensic summaries"""

import json
import os
import streamlit as st
import openai
from dotenv import load_dotenv

load_dotenv()

st.set_page_config(page_title="CloudTrail Forensics", page_icon="🔍", layout="wide")

@st.cache_data
def load_data():
    with open('llm_forensic_data.json', 'r') as f:
        return json.load(f)

@st.cache_data
def load_extended():
    try:
        with open('llm_forensic_extended.json', 'r') as f:
            return json.load(f)
    except:
        return None

def call_llm(prompt):
    api_key = os.getenv('OPENAI_API_KEY')
    client = openai.OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are a cloud security forensic analyst."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.7,
        max_tokens=1500
    )
    return response.choices[0].message.content

data = load_data()
extended = load_extended()

st.title("🔍 CloudTrail Forensic Analysis")

# Sidebar stats
with st.sidebar:
    st.header("Stats")
    stats = data.get('statistics', {})
    st.metric("Events", stats.get('total_events', '-'))
    st.metric("Users", stats.get('unique_users', '-'))
    st.metric("Error Rate", f"{stats.get('error_rate', 0):.1f}%")

# Analysis buttons
st.subheader("Generate Summaries")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("Attack Narrative", use_container_width=True):
        with st.spinner("Generating..."):
            st.session_state['result'] = call_llm(data['prompts']['narrative_generation'])

with col2:
    if st.button("User Behavior", use_container_width=True):
        with st.spinner("Generating..."):
            st.session_state['result'] = call_llm(data['prompts']['behavior_comparison'])

with col3:
    if st.button("Timeline", use_container_width=True):
        with st.spinner("Generating..."):
            st.session_state['result'] = call_llm(data['prompts']['timeline_reconstruction'])

# Extended analysis
if extended:
    st.subheader("Extended Analysis")
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Attack Phases", use_container_width=True):
            with st.spinner("Generating..."):
                st.session_state['result'] = call_llm(extended['prompts']['attack_phases'])
    with col2:
        if st.button("IP Intelligence", use_container_width=True):
            with st.spinner("Generating..."):
                st.session_state['result'] = call_llm(extended['prompts']['ip_intelligence'])
    with col3:
        if st.button("Error Patterns", use_container_width=True):
            with st.spinner("Generating..."):
                st.session_state['result'] = call_llm(extended['prompts']['error_forensics'])

# Q&A
st.subheader("Ask a Question")
question = st.text_input("", placeholder="e.g., What credentials were compromised?")
if st.button("Ask") and question:
    with st.spinner("Analyzing..."):
        prompt = f"{data['prompts']['qa_context']}\n\nQUESTION: {question}"
        st.session_state['result'] = call_llm(prompt)

# Display result
if 'result' in st.session_state:
    st.divider()
    st.markdown(st.session_state['result'])
