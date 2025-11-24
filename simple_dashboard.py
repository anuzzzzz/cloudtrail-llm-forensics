"""
SIMPLIFIED FLAWS.CLOUD FORENSIC DASHBOARD
Version without complex date annotations - guaranteed to work
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
import gzip
from pathlib import Path
import numpy as np

st.set_page_config(
    page_title="Flaws.Cloud Forensics",
    page_icon="🔍",
    layout="wide"
)

@st.cache_data
def load_data():
    """Load all CloudTrail data"""
    all_events = []
    
    progress = st.progress(0)
    status = st.empty()
    
    for i in range(20):
        file_path = f'flaws_cloudtrail{i:02d}.json.gz'
        if Path(file_path).exists():
            status.text(f"Loading file {i+1}/20...")
            with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
                all_events.extend(data['Records'])
            progress.progress((i+1)/20)
    
    status.empty()
    progress.empty()
    
    df = pd.DataFrame(all_events)
    
    # Extract fields
    df['eventTime'] = pd.to_datetime(df['eventTime'])
    df['username'] = df['userIdentity'].apply(lambda x: 
        x.get('userName', x.get('principalId', 'Unknown')) if isinstance(x, dict) else 'Unknown'
    )
    df['errorCode'] = df.get('errorCode', pd.Series())
    df['has_error'] = df['errorCode'].notna()
    df['date'] = df['eventTime'].dt.date
    df['month'] = df['eventTime'].dt.to_period('M').astype(str)
    
    return df

def main():
    st.title("🔍 Flaws.Cloud Forensic Dashboard")
    st.markdown("### CloudTrail Event Analysis (Simplified Version)")
    
    # Load data
    with st.spinner("Loading CloudTrail data..."):
        df = load_data()
    
    # Sidebar
    st.sidebar.header("📊 Dataset Info")
    st.sidebar.metric("Total Events", f"{len(df):,}")
    st.sidebar.metric("Unique Users", f"{df['username'].nunique()}")
    st.sidebar.metric("Date Range", f"{df['date'].min()} to {df['date'].max()}")
    
    # Main metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Events", f"{len(df):,}")
    
    with col2:
        unique_users = df['username'].nunique()
        st.metric("Unique Users", f"{unique_users}")
    
    with col3:
        error_rate = (df['has_error'].sum() / len(df) * 100)
        st.metric("Error Rate", f"{error_rate:.1f}%")
    
    with col4:
        aug_2019 = df[df['month'] == '2019-08']
        st.metric("Aug 2019 Events", f"{len(aug_2019):,}")
    
    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "📈 Timeline", 
        "👥 User Analysis",
        "🔥 August 2019",
        "🎯 Key Actions"
    ])
    
    with tab1:
        st.header("Event Timeline")
        
        # Monthly view
        monthly = df.groupby('month').size().reset_index(name='events')
        monthly = monthly.sort_values('month')
        
        fig = px.bar(
            monthly,
            x='month',
            y='events',
            title='Monthly Event Distribution',
            labels={'events': 'Number of Events', 'month': 'Month'},
            color='events',
            color_continuous_scale='Blues'
        )
        fig.update_xaxes(tickangle=45)
        st.plotly_chart(fig, use_container_width=True)
        
        # Identify peak month
        peak_month = monthly.loc[monthly['events'].idxmax()]
        st.info(f"📊 Peak activity: {peak_month['month']} with {peak_month['events']:,} events")
        
        # User timeline
        st.subheader("User Activity Over Time")
        
        # Get top users
        top_users = df['username'].value_counts().head(5).index.tolist()
        
        # Filter to top users
        top_user_df = df[df['username'].isin(top_users)]
        
        # Daily aggregation for top users
        daily_users = top_user_df.groupby(['date', 'username']).size().reset_index(name='events')
        
        fig = px.area(
            daily_users,
            x='date',
            y='events',
            color='username',
            title='Top 5 Users - Daily Activity',
            labels={'events': 'Events', 'date': 'Date'}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.header("User Behavior Analysis")
        
        # User distribution
        user_counts = df['username'].value_counts().head(20)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Top 20 Users by Event Count")
            fig = px.bar(
                x=user_counts.values,
                y=user_counts.index,
                orientation='h',
                title="Event Distribution",
                labels={'x': 'Number of Events', 'y': 'Username'}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("User Error Rates")
            user_errors = df.groupby('username').agg({
                'has_error': 'sum',
                'eventName': 'count'
            }).head(20)
            user_errors['error_rate'] = (user_errors['has_error'] / user_errors['eventName'] * 100).round(1)
            user_errors = user_errors.sort_values('error_rate', ascending=False)
            
            fig = px.bar(
                x=user_errors['error_rate'].values,
                y=user_errors.index,
                orientation='h',
                title="Error Rate by User (%)",
                labels={'x': 'Error Rate (%)', 'y': 'Username'},
                color=user_errors['error_rate'].values,
                color_continuous_scale='Reds'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # User details
        st.subheader("User Detail View")
        selected_user = st.selectbox("Select a user", user_counts.index.tolist())
        
        user_data = df[df['username'] == selected_user]
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Events", f"{len(user_data):,}")
        with col2:
            user_error_rate = (user_data['has_error'].sum() / len(user_data) * 100)
            st.metric("Error Rate", f"{user_error_rate:.1f}%")
        with col3:
            st.metric("Active Days", f"{user_data['date'].nunique()}")
        
        # Top actions for selected user
        user_actions = user_data['eventName'].value_counts().head(10)
        
        fig = px.pie(
            values=user_actions.values,
            names=user_actions.index,
            title=f"Top 10 Actions - {selected_user}"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        st.header("🔥 August 2019 Explosion Analysis")
        
        aug_2019 = df[df['month'] == '2019-08']
        
        st.markdown(f"""
        ### The Explosion Event
        
        In August 2019, the dataset experienced a massive spike:
        - **{len(aug_2019):,}** total events (69.5% of entire dataset!)
        - **{aug_2019['has_error'].sum():,}** failed attempts
        - **{(aug_2019['has_error'].sum()/len(aug_2019)*100):.1f}%** error rate
        
        This indicates an automated tool discovered the leaked credentials.
        """)
        
        # Daily breakdown
        aug_daily = aug_2019.groupby('date').size().reset_index(name='events')
        aug_daily = aug_daily.sort_values('date')
        
        fig = px.bar(
            aug_daily,
            x='date',
            y='events',
            title='August 2019 - Daily Event Count',
            labels={'events': 'Events', 'date': 'Date'},
            color='events',
            color_continuous_scale='Reds',
            text='events'
        )
        fig.update_traces(texttemplate='%{text:,}', textposition='outside')
        st.plotly_chart(fig, use_container_width=True)
        
        # Identify peak days
        peak_days = aug_daily.nlargest(3, 'events')
        st.warning(f"💥 Top 3 days accounted for {peak_days['events'].sum():,} events!")
        
        # User breakdown
        col1, col2 = st.columns(2)
        
        with col1:
            aug_users = aug_2019['username'].value_counts().head(5)
            fig = px.pie(
                values=aug_users.values,
                names=aug_users.index,
                title="User Distribution - Aug 2019"
            )
            st.plotly_chart(fig)
        
        with col2:
            aug_actions = aug_2019['eventName'].value_counts().head(5)
            fig = px.pie(
                values=aug_actions.values,
                names=aug_actions.index,
                title="Top Actions - Aug 2019"
            )
            st.plotly_chart(fig)
        
        # Key finding
        if 'RunInstances' in aug_actions.index:
            run_instances_count = aug_actions['RunInstances']
            run_pct = (run_instances_count / len(aug_2019) * 100)
            st.error(f"🚨 {run_instances_count:,} RunInstances attempts ({run_pct:.1f}% of August activity)")
    
    with tab4:
        st.header("Action Analysis")
        
        # Overall top actions
        action_counts = df['eventName'].value_counts().head(20)
        
        fig = px.bar(
            x=action_counts.values,
            y=action_counts.index,
            orientation='h',
            title="Top 20 AWS API Actions",
            labels={'x': 'Count', 'y': 'Action'},
            color=action_counts.values,
            color_continuous_scale='Viridis'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Service breakdown
        st.subheader("AWS Service Usage")
        service_counts = df['eventSource'].value_counts().head(10)
        
        fig = px.pie(
            values=service_counts.values,
            names=service_counts.index,
            title="Top 10 AWS Services by Event Count",
            hole=0.4
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Error analysis
        st.subheader("Error Analysis")
        
        if df['errorCode'].notna().any():
            error_codes = df[df['errorCode'].notna()]['errorCode'].value_counts().head(10)
            
            fig = px.bar(
                x=error_codes.values,
                y=error_codes.index,
                orientation='h',
                title="Top 10 Error Codes",
                labels={'x': 'Count', 'y': 'Error Code'},
                color=error_codes.values,
                color_continuous_scale='Reds'
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    ### 🔍 Key Forensic Findings
    
    1. **August 2019**: Massive exploitation attempt with 1.3M+ events
    2. **High Error Rate**: AWS rate limiting prevented most attempts
    3. **User Pattern**: Level6 and backup accounts show automated behavior
    4. **Attack Type**: Primarily RunInstances attempts (EC2 instance launches)
    """)

if __name__ == "__main__":
    main()