"""
FLAWS.CLOUD FORENSIC DASHBOARD
Interactive timeline and analysis dashboard for CloudTrail events
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import gzip
from pathlib import Path
import numpy as np

# Page configuration
st.set_page_config(
    page_title="Flaws.Cloud Forensic Timeline",
    page_icon="🔍",
    layout="wide"
)

@st.cache_data
def load_data():
    """Load and process all CloudTrail data"""
    all_events = []
    
    # Load all 20 gzip files
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
    
    status.text("Processing data...")
    
    # Convert to DataFrame
    df = pd.DataFrame(all_events)
    
    # Extract key fields
    df['eventTime'] = pd.to_datetime(df['eventTime'])
    df['username'] = df['userIdentity'].apply(extract_username)
    df['identity_type'] = df['userIdentity'].apply(lambda x: x.get('type') if isinstance(x, dict) else 'Unknown')
    df['errorCode'] = df.apply(lambda x: x.get('errorCode'), axis=1)
    df['has_error'] = df['errorCode'].notna()
    df['date'] = df['eventTime'].dt.date
    df['hour'] = df['eventTime'].dt.hour
    df['month'] = df['eventTime'].dt.to_period('M').astype(str)
    
    progress.empty()
    status.empty()
    
    return df

def extract_username(user_identity):
    """Extract username from userIdentity field"""
    if not isinstance(user_identity, dict):
        return 'Unknown'
    
    # Try different fields in order
    if 'userName' in user_identity:
        return user_identity['userName']
    elif 'principalId' in user_identity:
        principal = user_identity['principalId']
        # Handle different formats
        if ':' in str(principal):
            return principal.split(':')[-1]
        elif principal == user_identity.get('accountId'):
            return principal
        else:
            return principal
    elif 'type' in user_identity:
        if user_identity['type'] == 'Root':
            return 'flaws'
        elif user_identity['type'] == 'AWSService':
            return 'Unknown'
    
    return 'Unknown'

def create_timeline_chart(df, date_range):
    """Create interactive timeline chart"""
    filtered = df[(df['date'] >= date_range[0]) & (df['date'] <= date_range[1])]
    
    # Daily aggregation
    daily = filtered.groupby(['date', 'username']).size().reset_index(name='events')
    
    # Create stacked area chart
    fig = px.area(
        daily, 
        x='date', 
        y='events', 
        color='username',
        title='Event Timeline by User',
        labels={'events': 'Number of Events', 'date': 'Date'},
        height=400
    )
    
    # Add August 2019 explosion annotation
    explosion_date = pd.to_datetime('2019-08-22')
    explosion_date_only = explosion_date.date()
    if date_range[0] <= explosion_date_only <= date_range[1]:
        fig.add_vline(
            x=explosion_date.timestamp() * 1000,  # Convert to milliseconds timestamp
            line_dash="dash",
            line_color="red",
            annotation_text="August 2019 Explosion"
        )
    
    fig.update_layout(hovermode='x unified')
    return fig

def create_hourly_heatmap(df, selected_users):
    """Create hourly activity heatmap"""
    filtered = df[df['username'].isin(selected_users)].copy()

    # Create hour x day matrix
    # Use existing 'date' and 'hour' columns instead of extracting from eventTime
    hourly = filtered.groupby(['date', 'hour']).size().reset_index(name='count')
    
    # Pivot for heatmap
    matrix = hourly.pivot(index='hour', columns='date', values='count').fillna(0)
    
    # Limit to last 30 days for readability
    if matrix.shape[1] > 30:
        matrix = matrix.iloc[:, -30:]
    
    fig = go.Figure(data=go.Heatmap(
        z=matrix.values,
        x=[str(d) for d in matrix.columns],
        y=matrix.index,
        colorscale='Viridis',
        text=matrix.values.astype(int),
        texttemplate='%{text}',
        textfont={"size": 8},
        hoverongaps=False
    ))
    
    fig.update_layout(
        title='Hourly Activity Pattern (Last 30 Days)',
        xaxis_title='Date',
        yaxis_title='Hour of Day',
        height=400
    )
    
    return fig

def detect_anomalies(df):
    """Detect anomalous activity periods"""
    daily = df.groupby('date').size()
    
    # Calculate statistics
    mean = daily.mean()
    std = daily.std()
    threshold = mean + 3 * std
    
    # Find anomalies
    anomalies = daily[daily > threshold].sort_values(ascending=False)
    
    return anomalies, mean, std, threshold

def create_error_analysis(df):
    """Analyze error patterns"""
    errors = df[df['has_error']]
    
    # Top error codes
    error_counts = errors['errorCode'].value_counts().head(10)
    
    # Error rate by user
    user_errors = df.groupby('username').agg({
        'has_error': 'sum',
        'eventName': 'count'
    })
    user_errors['error_rate'] = (user_errors['has_error'] / user_errors['eventName'] * 100).round(1)
    user_errors = user_errors.sort_values('has_error', ascending=False).head(10)
    
    return error_counts, user_errors

def create_action_breakdown(df, username):
    """Create action breakdown for specific user"""
    user_events = df[df['username'] == username]
    
    # Top actions
    actions = user_events['eventName'].value_counts().head(20)
    
    fig = px.bar(
        x=actions.values, 
        y=actions.index,
        orientation='h',
        title=f'Top 20 Actions by {username}',
        labels={'x': 'Count', 'y': 'Action'}
    )
    
    fig.update_layout(height=500)
    return fig

def main():
    st.title("🔍 Flaws.Cloud Forensic Dashboard")
    st.markdown("### Interactive Timeline Analysis of CloudTrail Events")
    
    # Load data
    with st.spinner("Loading CloudTrail data..."):
        df = load_data()
    
    # Sidebar filters
    st.sidebar.header("🎛️ Filters")
    
    # Date range
    min_date = df['date'].min()
    max_date = df['date'].max()
    
    date_range = st.sidebar.date_input(
        "Select Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )
    
    # User filter
    all_users = df['username'].value_counts().head(20).index.tolist()
    
    # Only use defaults that actually exist in the top users
    default_users = [u for u in ['backup', 'Level6', 'Unknown', 'Level5'] if u in all_users]
    
    selected_users = st.sidebar.multiselect(
        "Select Users",
        options=all_users,
        default=default_users
    )
    
    # Main metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Events", f"{len(df):,}")
    
    with col2:
        st.metric("Unique Users", f"{df['username'].nunique():,}")
    
    with col3:
        error_rate = (df['has_error'].sum() / len(df) * 100)
        st.metric("Overall Error Rate", f"{error_rate:.1f}%")
    
    with col4:
        duration = (df['eventTime'].max() - df['eventTime'].min()).days
        st.metric("Dataset Duration", f"{duration} days")
    
    # Tabs for different views
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📈 Timeline", 
        "🚨 Anomalies", 
        "👥 User Analysis",
        "❌ Error Analysis",
        "🔥 August 2019 Deep Dive"
    ])
    
    with tab1:
        st.header("Timeline Visualization")
        
        # Timeline chart
        timeline_fig = create_timeline_chart(df, date_range)
        st.plotly_chart(timeline_fig, use_container_width=True)
        
        # Hourly heatmap
        if selected_users:
            hourly_fig = create_hourly_heatmap(df, selected_users)
            st.plotly_chart(hourly_fig, use_container_width=True)
    
    with tab2:
        st.header("Anomaly Detection")
        
        anomalies, mean, std, threshold = detect_anomalies(df)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Daily Average", f"{mean:.0f} events")
        with col2:
            st.metric("Standard Deviation", f"{std:.0f}")
        with col3:
            st.metric("Anomaly Threshold", f"{threshold:.0f} events")
        
        st.subheader("🚨 Detected Anomalies (>3σ)")
        
        if len(anomalies) > 0:
            anomaly_df = pd.DataFrame({
                'Date': anomalies.index,
                'Events': anomalies.values,
                'Sigma': ((anomalies.values - mean) / std).round(1)
            })
            anomaly_df['Flag'] = anomaly_df['Sigma'].apply(lambda x: '🔥' if x > 10 else '⚠️')
            
            st.dataframe(
                anomaly_df.style.background_gradient(subset=['Events'], cmap='Reds'),
                use_container_width=True
            )
            
            # Anomaly timeline
            fig = px.scatter(
                anomaly_df,
                x='Date',
                y='Events',
                size='Events',
                color='Sigma',
                hover_data=['Sigma'],
                title='Anomalous Days Timeline',
                color_continuous_scale='Reds'
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        st.header("User Behavior Analysis")
        
        # User selection
        selected_user = st.selectbox("Select User for Deep Dive", all_users)
        
        user_data = df[df['username'] == selected_user]
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Events", f"{len(user_data):,}")
        with col2:
            st.metric("Active Days", f"{user_data['date'].nunique():,}")
        with col3:
            user_error_rate = (user_data['has_error'].sum() / len(user_data) * 100)
            st.metric("Error Rate", f"{user_error_rate:.1f}%")
        with col4:
            first_seen = user_data['eventTime'].min()
            st.metric("First Seen", first_seen.strftime('%Y-%m-%d'))
        
        # Action breakdown
        action_fig = create_action_breakdown(df, selected_user)
        st.plotly_chart(action_fig, use_container_width=True)
        
        # Temporal pattern
        st.subheader(f"Temporal Pattern for {selected_user}")
        user_daily = user_data.groupby('date').size().reset_index(name='events')
        
        fig = px.line(
            user_daily,
            x='date',
            y='events',
            title=f'{selected_user} Daily Activity',
            markers=True
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with tab4:
        st.header("Error Analysis")
        
        error_counts, user_errors = create_error_analysis(df)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Top 10 Error Codes")
            error_df = pd.DataFrame({
                'Error Code': error_counts.index,
                'Count': error_counts.values
            })
            st.dataframe(error_df, use_container_width=True)
        
        with col2:
            st.subheader("Users with Most Errors")
            st.dataframe(
                user_errors[['has_error', 'error_rate']].rename(columns={
                    'has_error': 'Total Errors',
                    'error_rate': 'Error Rate %'
                }),
                use_container_width=True
            )
        
        # Error timeline
        st.subheader("Error Rate Over Time")
        daily_errors = df.groupby('date').agg({
            'has_error': 'sum',
            'eventName': 'count'
        })
        daily_errors['error_rate'] = (daily_errors['has_error'] / daily_errors['eventName'] * 100)
        
        fig = px.line(
            x=daily_errors.index,
            y=daily_errors['error_rate'],
            title='Daily Error Rate (%)',
            labels={'x': 'Date', 'y': 'Error Rate (%)'}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with tab5:
        st.header("🔥 August 2019 Explosion Analysis")
        
        aug_2019 = df[df['month'] == '2019-08']
        
        st.markdown("""
        ### The Story
        On August 21-23, 2019, the dataset experienced a massive spike in activity:
        - **1.3 million events** in just 3 days
        - **96.4%** were `RunInstances` attempts (trying to launch EC2 instances)
        - **97.5%** failure rate (AWS rate limiting kicked in)
        - Both `Level6` and `backup` users were equally active
        
        This pattern suggests an **automated tool or scanner** discovered the leaked credentials
        and attempted mass exploitation.
        """)
        
        # August daily breakdown
        aug_daily = aug_2019.groupby('date').size().reset_index(name='events')
        
        fig = px.bar(
            aug_daily,
            x='date',
            y='events',
            title='August 2019 Daily Events',
            labels={'events': 'Number of Events', 'date': 'Date'},
            color='events',
            color_continuous_scale='Reds'
        )
        
        # Add annotations for the explosion days
        for date in ['2019-08-21', '2019-08-22', '2019-08-23']:
            explosion_date = pd.to_datetime(date)
            explosion_date_only = explosion_date.date()
            if explosion_date_only in aug_daily['date'].values:
                count = aug_daily[aug_daily['date'] == explosion_date_only]['events'].values[0]
                fig.add_annotation(
                    x=explosion_date_only,  # Use date object instead of datetime
                    y=count,
                    text=f"💥 {count:,}",
                    showarrow=True,
                    arrowhead=2
                )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # User breakdown for August
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("User Activity in August 2019")
            aug_users = aug_2019['username'].value_counts().head(5)
            fig = px.pie(
                values=aug_users.values,
                names=aug_users.index,
                title="User Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Top Actions in August 2019")
            aug_actions = aug_2019['eventName'].value_counts().head(5)
            fig = px.pie(
                values=aug_actions.values,
                names=aug_actions.index,
                title="Action Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Hourly pattern during explosion
        explosion_days = aug_2019[aug_2019['date'].isin([
            pd.to_datetime('2019-08-21').date(),
            pd.to_datetime('2019-08-22').date(),
            pd.to_datetime('2019-08-23').date()
        ])]
        
        hourly_explosion = explosion_days.groupby('hour').size()
        
        st.subheader("Hourly Pattern During Explosion (Aug 21-23)")
        fig = px.bar(
            x=hourly_explosion.index,
            y=hourly_explosion.values,
            title="Events by Hour of Day",
            labels={'x': 'Hour', 'y': 'Events'}
        )
        st.plotly_chart(fig, use_container_width=True)

    # Footer with insights
    st.markdown("---")
    st.markdown("""
    ### 🔍 Key Forensic Insights
    
    1. **Credential Lifecycle**: The dataset shows clear progression from manual reconnaissance (Level5) 
       to automated exploitation (Level6/backup)
    2. **August 2019 Explosion**: Automated tool discovered leaked credentials and attempted mass exploitation
    3. **High Error Rates**: 77% overall failure rate indicates aggressive rate limiting by AWS
    4. **Temporal Patterns**: Clear working hours pattern for manual activity, 24/7 for automated tools
    """)

if __name__ == "__main__":
    main()