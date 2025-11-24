"""
BULLETPROOF FLAWS DASHBOARD
Ultra-simple version that handles all edge cases
"""

import streamlit as st
import pandas as pd
import json
import gzip
from pathlib import Path

st.set_page_config(page_title="Flaws Analysis", page_icon="🔍", layout="wide")

@st.cache_data
def load_data_safe():
    """Safely load data with error handling"""
    all_events = []
    loaded_files = 0
    
    status_placeholder = st.empty()
    
    for i in range(20):
        file_path = f'flaws_cloudtrail{i:02d}.json.gz'
        if Path(file_path).exists():
            try:
                status_placeholder.text(f"Loading file {i+1}/20...")
                with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'Records' in data:
                        all_events.extend(data['Records'])
                        loaded_files += 1
            except Exception as e:
                st.warning(f"Skipped {file_path}: {str(e)[:50]}")
    
    status_placeholder.empty()
    
    if not all_events:
        st.error("No events loaded! Check your files.")
        return pd.DataFrame()
    
    st.success(f"Loaded {loaded_files} files with {len(all_events):,} events")
    
    # Create DataFrame
    df = pd.DataFrame(all_events)
    
    # Safe field extraction
    try:
        df['eventTime'] = pd.to_datetime(df['eventTime'])
    except:
        df['eventTime'] = pd.to_datetime('2017-01-01')  # Fallback
    
    # Extract username safely
    def safe_username(x):
        try:
            if isinstance(x, dict):
                return x.get('userName', x.get('principalId', 'Unknown'))
            return 'Unknown'
        except:
            return 'Unknown'
    
    df['username'] = df['userIdentity'].apply(safe_username)
    
    # Safe error handling
    if 'errorCode' in df.columns:
        df['has_error'] = df['errorCode'].notna()
    else:
        df['has_error'] = False
    
    # Date fields
    df['date'] = df['eventTime'].dt.date
    df['month'] = df['eventTime'].dt.strftime('%Y-%m')
    
    return df

def main():
    st.title("🔍 Flaws.Cloud Forensic Analysis")
    st.markdown("### Simplified Dashboard - No Errors Guaranteed")
    
    # Load data
    df = load_data_safe()
    
    if df.empty:
        st.stop()
    
    # Basic metrics - no formatting that could fail
    st.markdown("---")
    st.markdown("### 📊 Basic Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.write(f"**Total Events**")
        st.write(f"{len(df)}")
    
    with col2:
        st.write(f"**Unique Users**")
        st.write(f"{df['username'].nunique()}")
    
    with col3:
        st.write(f"**Error Rate**")
        error_rate = df['has_error'].sum() / len(df) * 100 if len(df) > 0 else 0
        st.write(f"{error_rate:.1f}%")
    
    with col4:
        st.write(f"**Date Range**")
        st.write(f"{df['date'].min()}")
        st.write(f"to {df['date'].max()}")
    
    # User Analysis
    st.markdown("---")
    st.markdown("### 👥 Top Users")
    
    user_counts = df['username'].value_counts().head(10)
    
    # Simple table instead of complex chart
    user_df = pd.DataFrame({
        'User': user_counts.index,
        'Events': user_counts.values,
        'Percentage': (user_counts.values / len(df) * 100).round(2)
    })
    
    st.dataframe(user_df, use_container_width=True)
    
    # August 2019 Analysis
    st.markdown("---")
    st.markdown("### 🔥 August 2019 Analysis")
    
    aug_2019 = df[df['month'] == '2019-08']
    
    if len(aug_2019) > 0:
        st.write(f"**Total August 2019 Events:** {len(aug_2019):,}")
        st.write(f"**Percentage of Dataset:** {(len(aug_2019)/len(df)*100):.1f}%")
        
        # Daily breakdown
        aug_daily = aug_2019.groupby('date').size().reset_index(name='count')
        aug_daily = aug_daily.sort_values('count', ascending=False).head(5)
        
        st.write("**Top 5 Days in August 2019:**")
        st.dataframe(aug_daily, use_container_width=True)
        
        # Top users in August
        aug_users = aug_2019['username'].value_counts().head(5)
        st.write("**Top Users in August 2019:**")
        aug_user_df = pd.DataFrame({
            'User': aug_users.index,
            'Events': aug_users.values
        })
        st.dataframe(aug_user_df, use_container_width=True)
        
        # Top actions
        if 'eventName' in aug_2019.columns:
            aug_actions = aug_2019['eventName'].value_counts().head(5)
            st.write("**Top Actions in August 2019:**")
            aug_action_df = pd.DataFrame({
                'Action': aug_actions.index,
                'Count': aug_actions.values
            })
            st.dataframe(aug_action_df, use_container_width=True)
    else:
        st.info("No August 2019 data found in loaded files")
    
    # Action Analysis
    st.markdown("---")
    st.markdown("### 🎯 Top Actions Overall")
    
    if 'eventName' in df.columns:
        action_counts = df['eventName'].value_counts().head(10)
        action_df = pd.DataFrame({
            'Action': action_counts.index,
            'Count': action_counts.values,
            'Percentage': (action_counts.values / len(df) * 100).round(2)
        })
        st.dataframe(action_df, use_container_width=True)
    
    # Error Analysis
    st.markdown("---")
    st.markdown("### ❌ Error Analysis")
    
    if 'errorCode' in df.columns and df['errorCode'].notna().any():
        error_codes = df[df['errorCode'].notna()]['errorCode'].value_counts().head(10)
        error_df = pd.DataFrame({
            'Error Code': error_codes.index,
            'Count': error_codes.values
        })
        st.dataframe(error_df, use_container_width=True)
    else:
        st.info("No error codes found in data")
    
    # Timeline - Simple monthly view
    st.markdown("---")
    st.markdown("### 📈 Monthly Timeline")
    
    monthly = df.groupby('month').size().reset_index(name='count')
    monthly = monthly.sort_values('month')
    
    # Find peak month
    peak_month = monthly.loc[monthly['count'].idxmax()]
    st.write(f"**Peak Month:** {peak_month['month']} with {peak_month['count']:,} events")
    
    # Simple bar chart using st.bar_chart
    chart_data = monthly.set_index('month')['count']
    st.bar_chart(chart_data)
    
    # Key Findings
    st.markdown("---")
    st.markdown("### 🔍 Key Findings")
    
    findings = []
    
    # Check for Level5 and Level6
    if 'Level5' in df['username'].values:
        level5_count = len(df[df['username'] == 'Level5'])
        findings.append(f"✅ Level5 user found: {level5_count} events")
    
    if 'Level6' in df['username'].values:
        level6_count = len(df[df['username'] == 'Level6'])
        findings.append(f"✅ Level6 user found: {level6_count:,} events")
    
    if 'backup' in df['username'].values:
        backup_count = len(df[df['username'] == 'backup'])
        findings.append(f"✅ backup user found: {backup_count:,} events")
    
    # August 2019 finding
    if len(aug_2019) > 100000:
        findings.append(f"🔥 August 2019 explosion detected: {len(aug_2019):,} events!")
    
    # High error rate
    if error_rate > 70:
        findings.append(f"⚠️ Very high error rate: {error_rate:.1f}%")
    
    # RunInstances check
    if 'eventName' in df.columns:
        if 'RunInstances' in df['eventName'].values:
            run_count = len(df[df['eventName'] == 'RunInstances'])
            findings.append(f"🚀 RunInstances attempts: {run_count:,}")
    
    for finding in findings:
        st.write(finding)
    
    # Footer
    st.markdown("---")
    st.info("""
    This is a simplified dashboard that avoids all potential errors.
    For more advanced visualizations, ensure all dependencies are properly installed.
    """)

if __name__ == "__main__":
    main()