import pandas as pd
import json
import gzip
from pathlib import Path
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

print("=" * 80)
print("FLAWS.CLOUD CLOUDTRAIL - GRAPH FEASIBILITY DIAGNOSTIC")
print("=" * 80)

# Load all CloudTrail logs
def load_cloudtrail_logs(data_dir='.'):
    """Load all gzipped CloudTrail JSON files"""
    all_events = []
    files = sorted(Path(data_dir).glob('flaws_cloudtrail*.json.gz'))
    
    print(f"\n📂 Loading {len(files)} files...")
    
    for i, file in enumerate(files):
        with gzip.open(file, 'rt', encoding='utf-8') as f:
            data = json.load(f)
            all_events.extend(data['Records'])
        if (i + 1) % 5 == 0:
            print(f"   Loaded {i + 1}/{len(files)} files... ({len(all_events):,} events so far)")
    
    print(f"✅ Total events loaded: {len(all_events):,}\n")
    return pd.DataFrame(all_events)

# Load data
df = load_cloudtrail_logs()

print("=" * 80)
print("1. DATASET OVERVIEW")
print("=" * 80)
print(f"Total Events: {len(df):,}")
print(f"Date Range: {df['eventTime'].min()} → {df['eventTime'].max()}")
print(f"Memory Usage: {df.memory_usage(deep=True).sum() / 1024**2:.1f} MB")
print(f"Columns: {len(df.columns)}")

print("\n" + "=" * 80)
print("2. GRAPH-CRITICAL EVENTS (Do edges exist?)")
print("=" * 80)

# Graph-relevant event types
graph_events = [
    'AssumeRole',           # IAM role switching (PRIMARY EDGE!)
    'GetSessionToken',      # Temporary credentials
    'GetFederationToken',   # Federated access
    'AttachUserPolicy',     # Policy attachment
    'PutUserPolicy',        # Inline policy creation
    'AttachRolePolicy',     # Role policy changes
    'PutRolePolicy',        # Inline role policy
]

event_counts = df['eventName'].value_counts()
print("\n�� Graph-Relevant Events:")
for event in graph_events:
    count = event_counts.get(event, 0)
    status = "✅" if count > 0 else "❌"
    print(f"   {status} {event}: {count:,}")

total_graph_events = sum(event_counts.get(e, 0) for e in graph_events)
print(f"\n   TOTAL GRAPH SIGNALS: {total_graph_events:,} ({total_graph_events/len(df)*100:.2f}%)")

print("\n" + "=" * 80)
print("3. CORE ATTACK USERS (Are the 5 users present?)")
print("=" * 80)

# Extract usernames
df['username'] = df['userIdentity'].apply(
    lambda x: x.get('userName', x.get('principalId', 'Unknown')) if isinstance(x, dict) else 'Unknown'
)

# Known attack users
attack_users = ['Level1', 'Level2', 'Level3', 'Level4', 'Level5', 'Level6', 'backup', 'SecurityMonkey']

print("\n👤 Attack User Activity:")
user_counts = df['username'].value_counts()
for user in attack_users:
    count = user_counts.get(user, 0)
    status = "✅" if count > 0 else "❌"
    print(f"   {status} {user}: {count:,} events")

print("\n📊 Top 10 Users Overall:")
for user, count in user_counts.head(10).items():
    print(f"   {user}: {count:,}")

print("\n" + "=" * 80)
print("4. TEMPORAL PROGRESSION (Can we trace attack sequence?)")
print("=" * 80)

# Convert to datetime
df['eventTime'] = pd.to_datetime(df['eventTime'])

# Filter to core attack users
core_users_df = df[df['username'].isin(attack_users)].copy()
print(f"\n📅 Core Attack User Events: {len(core_users_df):,} ({len(core_users_df)/len(df)*100:.2f}%)")

if len(core_users_df) > 0:
    print("\n⏰ Timeline by User:")
    for user in attack_users:
        user_df = core_users_df[core_users_df['username'] == user]
        if len(user_df) > 0:
            print(f"   {user}: {user_df['eventTime'].min()} → {user_df['eventTime'].max()} ({len(user_df):,} events)")

print("\n" + "=" * 80)
print("5. ASSUME ROLE ANALYSIS (Primary graph edges)")
print("=" * 80)

assume_role_df = df[df['eventName'] == 'AssumeRole'].copy()
print(f"\n🔗 AssumeRole Events: {len(assume_role_df):,}")

if len(assume_role_df) > 0:
    # Extract source and target
    assume_role_df['source'] = assume_role_df['userIdentity'].apply(
        lambda x: x.get('arn', 'Unknown') if isinstance(x, dict) else 'Unknown'
    )
    assume_role_df['target'] = assume_role_df['requestParameters'].apply(
        lambda x: x.get('roleArn', 'Unknown') if isinstance(x, dict) else 'Unknown'
    )
    
    # Count edges
    edges = assume_role_df.groupby(['source', 'target']).size().sort_values(ascending=False)
    print(f"\n   Unique Edges (User → Role): {len(edges)}")
    print(f"\n   Top 10 Role Assumptions:")
    for (src, tgt), count in edges.head(10).items():
        src_short = src.split('/')[-1] if '/' in src else src
        tgt_short = tgt.split('/')[-1] if '/' in tgt else tgt
        print(f"      {src_short} → {tgt_short}: {count:,} times")

print("\n" + "=" * 80)
print("6. DATA QUALITY CHECK")
print("=" * 80)

critical_fields = ['eventName', 'userIdentity', 'eventTime', 'sourceIPAddress']
print("\n🔍 Missing Critical Fields:")
for field in critical_fields:
    null_count = df[field].isnull().sum()
    null_pct = null_count / len(df) * 100
    status = "✅" if null_pct < 1 else "⚠️"
    print(f"   {status} {field}: {null_count:,} missing ({null_pct:.2f}%)")

print("\n" + "=" * 80)
print("7. VERDICT: GRAPH ANALYSIS FEASIBILITY")
print("=" * 80)

# Decision criteria
has_graph_events = total_graph_events > 100
has_core_users = len(core_users_df) > 1000
has_assume_role = len(assume_role_df) > 10
data_quality_ok = df['eventName'].isnull().sum() < len(df) * 0.05

print("\n✅ = GO | ❌ = NO-GO\n")
print(f"   {'✅' if has_graph_events else '❌'} Graph Events Present: {total_graph_events:,} (need >100)")
print(f"   {'✅' if has_core_users else '❌'} Core User Activity: {len(core_users_df):,} (need >1000)")
print(f"   {'✅' if has_assume_role else '❌'} AssumeRole Edges: {len(assume_role_df):,} (need >10)")
print(f"   {'✅' if data_quality_ok else '❌'} Data Quality: {df['eventName'].isnull().sum():,} missing events")

if has_graph_events and has_core_users and has_assume_role and data_quality_ok:
    print("\n🎯 VERDICT: GRAPH ANALYSIS IS VIABLE ✅")
    print("   → Proceed with graph construction")
    print("   → Focus on AssumeRole edges")
    print("   → Temporal attack progression is traceable")
else:
    print("\n⚠️ VERDICT: GRAPH ANALYSIS MAY BE LIMITED")
    print("   → Consider alternative approaches")
    print("   → Data may be too sparse for meaningful graph")

print("\n" + "=" * 80)
