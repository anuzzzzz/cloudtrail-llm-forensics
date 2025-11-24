#!/usr/bin/env python3
"""Extended LLM forensic analysis with deep behavioral insights"""

import pandas as pd
import json
import gzip
from pathlib import Path
import numpy as np
from collections import defaultdict

print("Loading CloudTrail data...")

all_events = []
for i in range(20):
    file_path = f'flaws_cloudtrail{i:02d}.json.gz'
    if Path(file_path).exists():
        with gzip.open(file_path, 'rt') as f:
            data = json.load(f)
            all_events.extend(data['Records'])

df = pd.DataFrame(all_events)
df['eventTime'] = pd.to_datetime(df['eventTime'])
df['username'] = df['userIdentity'].apply(lambda x:
    x.get('userName', x.get('principalId', 'Unknown')) if isinstance(x, dict) else 'Unknown'
)
df['date'] = df['eventTime'].dt.date
df['hour'] = df['eventTime'].dt.hour

print(f"Loaded {len(df):,} events\n")

# Attack Phase Detection
def detect_attack_phases(df):
    phases = []

    # Phase 1: Level5 Reconnaissance
    level5 = df[df['username'] == 'Level5']
    if len(level5) > 0:
        phases.append({
            'phase': 'Initial_Reconnaissance',
            'start': str(level5['eventTime'].min()),
            'end': str(level5['eventTime'].max()),
            'duration_hours': (level5['eventTime'].max() - level5['eventTime'].min()).total_seconds() / 3600,
            'events': len(level5),
            'unique_actions': level5['eventName'].nunique(),
            'action_sequence': list(level5.sort_values('eventTime')['eventName'].values),
            'services': list(level5['eventSource'].unique())
        })

    # Phase 2: August Explosion
    explosion = df[df['date'].astype(str).str.startswith('2019-08-2')]
    if len(explosion) > 0:
        phases.append({
            'phase': 'Mass_Exploitation',
            'start': '2019-08-21',
            'end': '2019-08-23',
            'total_events': len(explosion),
            'hourly_peak': int(explosion.groupby(explosion['eventTime'].dt.floor('H')).size().max()),
            'unique_ips': explosion['sourceIPAddress'].nunique(),
            'runinstances_attempts': len(explosion[explosion['eventName'] == 'RunInstances']),
            'error_rate': float(explosion['errorCode'].notna().sum() / len(explosion) * 100) if 'errorCode' in explosion.columns else 0
        })

    return phases

# IP Intelligence
def analyze_ip_patterns(df):
    ip_analysis = {
        'total_unique_ips': df['sourceIPAddress'].nunique(),
        'top_ips': {}
    }

    for ip in df['sourceIPAddress'].value_counts().head(10).index:
        ip_df = df[df['sourceIPAddress'] == ip]
        ip_analysis['top_ips'][ip] = {
            'users': list(ip_df['username'].unique()),
            'events': len(ip_df),
            'top_actions': ip_df['eventName'].value_counts().head(3).to_dict()
        }

    return ip_analysis

# Behavioral Sequences
def extract_sequences(df, user, max_sessions=5):
    user_df = df[df['username'] == user].sort_values('eventTime')
    user_df['time_diff'] = user_df['eventTime'].diff()
    user_df['session'] = (user_df['time_diff'] > pd.Timedelta(hours=1)).cumsum()

    sequences = []
    for session_id, session in user_df.groupby('session'):
        if len(session) > 5 and len(sequences) < max_sessions:
            sequences.append({
                'session': int(session_id),
                'start': str(session['eventTime'].min()),
                'duration_minutes': (session['eventTime'].max() - session['eventTime'].min()).total_seconds() / 60,
                'actions': list(session['eventName'].values)[:20]
            })

    return sequences

# Error Analysis
def analyze_errors(df):
    errors = df[df['errorCode'].notna()]

    analysis = {
        'total_errors': len(errors),
        'error_rate': float(len(errors) / len(df) * 100),
        'top_errors': errors['errorCode'].value_counts().head(5).to_dict(),
        'by_user': {}
    }

    for user in ['Level5', 'Level6', 'backup']:
        user_errors = errors[errors['username'] == user]
        if len(user_errors) > 0:
            analysis['by_user'][user] = {
                'errors': len(user_errors),
                'error_rate': float(len(user_errors) / len(df[df['username'] == user]) * 100),
                'top_failures': user_errors['eventName'].value_counts().head(3).to_dict()
            }

    return analysis

# User Correlations
def analyze_correlations(df):
    correlations = {'shared_ips': []}

    for ip in df['sourceIPAddress'].value_counts().head(20).index:
        users = df[df['sourceIPAddress'] == ip]['username'].unique()
        if len(users) > 1:
            correlations['shared_ips'].append({
                'ip': ip,
                'users': list(users),
                'events': len(df[df['sourceIPAddress'] == ip])
            })

    return correlations

# Hourly breakdown for August 2019
def get_hourly_explosion(df):
    aug_df = df[df['date'].astype(str).str.startswith('2019-08')]
    hourly = []

    for hour, group in aug_df.groupby(aug_df['eventTime'].dt.floor('H')):
        if len(group) > 1000:
            hourly.append({
                'hour': str(hour),
                'events': len(group),
                'users': group['username'].value_counts().to_dict(),
                'top_action': group['eventName'].value_counts().index[0],
                'error_rate': float(group['errorCode'].notna().sum() / len(group) * 100) if 'errorCode' in group.columns else 0
            })

    return hourly

print("Running extended analysis...")

# Execute all analyses
attack_phases = detect_attack_phases(df)
ip_intel = analyze_ip_patterns(df)
behavioral_seqs = {
    'Level5': extract_sequences(df, 'Level5'),
    'Level6': extract_sequences(df, 'Level6'),
    'backup': extract_sequences(df, 'backup')
}
error_analysis = analyze_errors(df)
user_correlations = analyze_correlations(df)
hourly_explosion = get_hourly_explosion(df)

# Create extended prompts
prompts = {
    'attack_phases': f"""Analyze these distinct attack phases:

{json.dumps(attack_phases, indent=2)}

Questions:
1. How does each phase differ in behavior and intent?
2. What triggered the transition from reconnaissance to mass exploitation?
3. Is this consistent with credential leakage patterns?""",

    'ip_intelligence': f"""Analyze IP address patterns:

Total unique IPs: {ip_intel['total_unique_ips']}

Top IPs and their behavior:
{json.dumps(ip_intel['top_ips'], indent=2)}

Questions:
1. What do IP patterns reveal about attacker infrastructure?
2. Is this coordinated or opportunistic?
3. How many distinct threat actors are involved?""",

    'behavioral_sequences': f"""Analyze user behavioral sequences:

Level5 (Reconnaissance):
{json.dumps(behavioral_seqs['Level5'], indent=2)}

Level6 (Exploitation):
{json.dumps(behavioral_seqs['Level6'][:2], indent=2)}

Questions:
1. How does manual reconnaissance differ from automated exploitation?
2. What specific actions reveal attacker intent?
3. Can you reconstruct the discovery process?""",

    'error_forensics': f"""Analyze error patterns:

{json.dumps(error_analysis, indent=2)}

Questions:
1. What do errors reveal about AWS defensive measures?
2. How did attackers adapt to rate limiting?
3. Which AWS security controls were most effective?""",

    'correlation_analysis': f"""Analyze cross-user correlations:

{json.dumps(user_correlations, indent=2)}

Questions:
1. Are Level6 and backup the same attacker?
2. What evidence supports coordination vs opportunistic abuse?
3. How was the attack campaign organized?""",

    'explosion_timeline': f"""Analyze hourly breakdown of August 2019 explosion:

{json.dumps(hourly_explosion[:20], indent=2)}

Questions:
1. At what exact hour did the explosion start?
2. What was the peak intensity and why?
3. How did the attack evolve hour by hour?"""
}

# Save extended analysis
extended_data = {
    'attack_phases': attack_phases,
    'ip_intelligence': ip_intel,
    'behavioral_sequences': behavioral_seqs,
    'error_analysis': error_analysis,
    'user_correlations': user_correlations,
    'hourly_explosion': hourly_explosion,
    'prompts': prompts,
    'statistics': {
        'total_events': len(df),
        'date_range': f"{df['eventTime'].min()} to {df['eventTime'].max()}",
        'unique_users': df['username'].nunique(),
        'unique_ips': df['sourceIPAddress'].nunique(),
        'total_errors': error_analysis['total_errors'],
        'overall_error_rate': error_analysis['error_rate']
    }
}

with open('llm_forensic_extended.json', 'w') as f:
    json.dump(extended_data, f, indent=2, default=str)

print(f"✅ Extended analysis saved to llm_forensic_extended.json")
print(f"\nGenerated {len(prompts)} specialized prompts:")
for name in prompts.keys():
    print(f"  - {name}")
