#!/usr/bin/env python3
"""
CloudTrail Forensic Analysis with LLM
Comprehensive analysis combining basic and extended insights
"""

import pandas as pd
import json
import gzip
from pathlib import Path
from collections import defaultdict

def load_cloudtrail_data():
    """Load all CloudTrail logs from compressed JSON files"""
    all_events = []
    for i in range(20):
        file_path = f'flaws_cloudtrail{i:02d}.json.gz'
        if Path(file_path).exists():
            with gzip.open(file_path, 'rt') as f:
                data = json.load(f)
                all_events.extend(data['Records'])

    # Create DataFrame with essential columns
    df = pd.DataFrame(all_events)
    df['eventTime'] = pd.to_datetime(df['eventTime'])
    df['username'] = df['userIdentity'].apply(lambda x:
        x.get('userName', x.get('principalId', 'Unknown')) if isinstance(x, dict) else 'Unknown'
    )
    df['date'] = df['eventTime'].dt.date
    df['hour'] = df['eventTime'].dt.hour

    return df

def get_daily_summaries(df, threshold=100):
    """Create daily activity summaries for anomaly detection"""
    summaries = []
    for date, group in df.groupby('date'):
        if len(group) > threshold:
            summaries.append({
                'date': str(date),
                'total_events': len(group),
                'unique_users': group['username'].nunique(),
                'top_users': group['username'].value_counts().head(3).to_dict(),
                'top_actions': group['eventName'].value_counts().head(5).to_dict(),
                'error_rate': float(group['errorCode'].notna().sum() / len(group) * 100) if 'errorCode' in group.columns else 0
            })

    # Sort by event count to identify anomalies
    summaries.sort(key=lambda x: x['total_events'], reverse=True)
    return summaries

def get_user_profiles(df):
    """Extract behavioral profiles for key users"""
    profiles = {}
    for user in ['Level5', 'Level6', 'backup']:
        user_df = df[df['username'] == user]
        if len(user_df) > 0:
            profiles[user] = {
                'total_events': len(user_df),
                'date_range': f"{user_df['eventTime'].min()} to {user_df['eventTime'].max()}",
                'unique_actions': user_df['eventName'].nunique(),
                'top_actions': user_df['eventName'].value_counts().head(5).to_dict(),
                'error_rate': float(user_df['errorCode'].notna().sum() / len(user_df) * 100) if 'errorCode' in user_df.columns else 0,
                'unique_ips': user_df['sourceIPAddress'].nunique()
            }
    return profiles

def detect_attack_phases(df):
    """Identify distinct phases in the attack lifecycle"""
    phases = []

    # Phase 1: Level5 reconnaissance
    level5 = df[df['username'] == 'Level5'].sort_values('eventTime')
    if len(level5) > 0:
        phases.append({
            'phase': 'Reconnaissance',
            'user': 'Level5',
            'start': str(level5['eventTime'].min()),
            'end': str(level5['eventTime'].max()),
            'events': len(level5),
            'actions': list(level5['eventName'].values)
        })

    # Phase 2: August 2019 mass exploitation
    explosion = df[df['date'].astype(str).str.startswith('2019-08-2')]
    if len(explosion) > 0:
        phases.append({
            'phase': 'Mass_Exploitation',
            'start': '2019-08-21',
            'end': '2019-08-23',
            'events': len(explosion),
            'peak_hour': int(explosion.groupby(explosion['eventTime'].dt.floor('h')).size().max()),
            'runinstances_attempts': len(explosion[explosion['eventName'] == 'RunInstances']),
            'error_rate': float(explosion['errorCode'].notna().sum() / len(explosion) * 100) if 'errorCode' in explosion.columns else 0
        })

    return phases

def analyze_ip_patterns(df):
    """Extract IP address intelligence"""
    top_ips = {}
    for ip in df['sourceIPAddress'].value_counts().head(10).index:
        ip_df = df[df['sourceIPAddress'] == ip]
        top_ips[ip] = {
            'users': list(ip_df['username'].unique()),
            'events': len(ip_df),
            'top_actions': ip_df['eventName'].value_counts().head(3).to_dict()
        }

    return {
        'total_unique_ips': df['sourceIPAddress'].nunique(),
        'top_ips': top_ips
    }

def extract_behavioral_sequences(df, user, max_sessions=3):
    """Extract session-based behavioral sequences"""
    user_df = df[df['username'] == user].sort_values('eventTime')
    if len(user_df) == 0:
        return []

    # Split into sessions (1 hour gap = new session)
    user_df['time_diff'] = user_df['eventTime'].diff()
    user_df['session'] = (user_df['time_diff'] > pd.Timedelta(hours=1)).cumsum()

    sequences = []
    for session_id, session in user_df.groupby('session'):
        if len(session) > 5 and len(sequences) < max_sessions:
            sequences.append({
                'session': int(session_id),
                'start': str(session['eventTime'].min()),
                'duration_minutes': (session['eventTime'].max() - session['eventTime'].min()).total_seconds() / 60,
                'actions': list(session['eventName'].values)[:15]
            })

    return sequences

def analyze_errors(df):
    """Analyze error patterns and AWS defensive measures"""
    errors = df[df['errorCode'].notna()]

    analysis = {
        'total_errors': len(errors),
        'error_rate': float(len(errors) / len(df) * 100),
        'top_errors': errors['errorCode'].value_counts().head(5).to_dict()
    }

    # Per-user error analysis
    for user in ['Level5', 'Level6', 'backup']:
        user_errors = errors[errors['username'] == user]
        if len(user_errors) > 0:
            analysis[f'{user}_errors'] = {
                'count': len(user_errors),
                'rate': float(len(user_errors) / len(df[df['username'] == user]) * 100),
                'top_failures': user_errors['eventName'].value_counts().head(3).to_dict()
            }

    return analysis

def find_correlations(df):
    """Find cross-user correlations and shared infrastructure"""
    shared_ips = []
    for ip in df['sourceIPAddress'].value_counts().head(15).index:
        users = df[df['sourceIPAddress'] == ip]['username'].unique()
        if len(users) > 1:
            shared_ips.append({
                'ip': ip,
                'users': list(users),
                'events': len(df[df['sourceIPAddress'] == ip])
            })

    return {'shared_ips': shared_ips}

def get_hourly_explosion(df):
    """Get hour-by-hour breakdown of August 2019 explosion"""
    aug_df = df[df['date'].astype(str).str.startswith('2019-08')]
    hourly = []

    for hour, group in aug_df.groupby(aug_df['eventTime'].dt.floor('h')):
        if len(group) > 1000:
            hourly.append({
                'hour': str(hour),
                'events': len(group),
                'top_user': group['username'].value_counts().index[0],
                'top_action': group['eventName'].value_counts().index[0],
                'error_rate': float(group['errorCode'].notna().sum() / len(group) * 100) if 'errorCode' in group.columns else 0
            })

    return hourly

def create_prompts(daily_summaries, user_profiles, attack_phases, ip_intel,
                   behavioral_seqs, error_analysis, correlations, hourly_explosion):
    """Create comprehensive LLM prompts for all analysis types"""

    prompts = {
        'narrative': f"""Analyze this CloudTrail attack pattern:

Top 5 anomalous days:
{json.dumps(daily_summaries[:5], indent=2)}

User profiles:
{json.dumps(user_profiles, indent=2)}

Questions:
1. What type of attack is this?
2. Is this manual or automated?
3. What was the attacker trying to achieve?""",

        'timeline': f"""Reconstruct the attack timeline:

Attack phases:
{json.dumps(attack_phases, indent=2)}

User profiles:
{json.dumps(user_profiles, indent=2)}

Build a forensic timeline explaining the progression from reconnaissance to exploitation.""",

        'user_comparison': f"""Compare user behaviors:

{json.dumps(user_profiles, indent=2)}

Explain the differences between Level5 (reconnaissance) and Level6 (exploitation).""",

        'attack_phases': f"""Analyze distinct attack phases:

{json.dumps(attack_phases, indent=2)}

How does each phase differ in behavior and intent?""",

        'ip_intelligence': f"""Analyze IP patterns:

{json.dumps(ip_intel, indent=2)}

What do these patterns reveal about attacker infrastructure and coordination?""",

        'behavioral_sequences': f"""Analyze behavioral sequences:

Level5: {json.dumps(behavioral_seqs.get('Level5', []), indent=2)}
Level6: {json.dumps(behavioral_seqs.get('Level6', [])[:2], indent=2)}

How does manual reconnaissance differ from automated exploitation?""",

        'error_forensics': f"""Analyze error patterns:

{json.dumps(error_analysis, indent=2)}

What do errors reveal about AWS defensive measures and attacker adaptation?""",

        'correlations': f"""Analyze user correlations:

{json.dumps(correlations, indent=2)}

Are Level6 and backup the same attacker? What evidence supports this?""",

        'explosion_timeline': f"""Hour-by-hour August 2019 explosion:

{json.dumps(hourly_explosion[:15], indent=2)}

At what hour did the explosion start? What was the peak intensity?"""
    }

    return prompts

def main():
    """Main execution"""
    print("Loading CloudTrail data...")
    df = load_cloudtrail_data()
    print(f"Loaded {len(df):,} events\n")

    print("Generating analysis...")

    # Basic analysis
    daily_summaries = get_daily_summaries(df)
    user_profiles = get_user_profiles(df)

    # Extended analysis
    attack_phases = detect_attack_phases(df)
    ip_intel = analyze_ip_patterns(df)
    behavioral_seqs = {
        'Level5': extract_behavioral_sequences(df, 'Level5'),
        'Level6': extract_behavioral_sequences(df, 'Level6'),
        'backup': extract_behavioral_sequences(df, 'backup')
    }
    error_analysis = analyze_errors(df)
    correlations = find_correlations(df)
    hourly_explosion = get_hourly_explosion(df)

    # Create prompts
    prompts = create_prompts(daily_summaries, user_profiles, attack_phases,
                            ip_intel, behavioral_seqs, error_analysis,
                            correlations, hourly_explosion)

    # Save complete analysis
    output = {
        'statistics': {
            'total_events': len(df),
            'date_range': f"{df['eventTime'].min()} to {df['eventTime'].max()}",
            'unique_users': df['username'].nunique(),
            'unique_ips': df['sourceIPAddress'].nunique()
        },
        'daily_summaries': daily_summaries,
        'user_profiles': user_profiles,
        'attack_phases': attack_phases,
        'ip_intelligence': ip_intel,
        'behavioral_sequences': behavioral_seqs,
        'error_analysis': error_analysis,
        'correlations': correlations,
        'hourly_explosion': hourly_explosion,
        'prompts': prompts
    }

    with open('forensic_analysis.json', 'w') as f:
        json.dump(output, f, indent=2, default=str)

    print(f"Analysis complete: forensic_analysis.json")
    print(f"Generated {len(prompts)} analysis prompts")

if __name__ == "__main__":
    main()
