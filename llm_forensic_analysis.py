#!/usr/bin/env python3
"""
LLM-POWERED FORENSIC ANALYSIS THAT ACTUALLY WORKS
The right way to use LLMs with CloudTrail data
"""

import pandas as pd
import json
import gzip
from pathlib import Path
from datetime import datetime
import os

print("\n" + "="*60)
print("LLM-READY FORENSIC ANALYSIS")
print("="*60)

# Step 1: Load and PRE-PROCESS data into LLM-digestible format
print("\n[1] Pre-processing CloudTrail into LLM-ready chunks...")

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

print(f"Loaded {len(df):,} events")

# ============================================================
# APPROACH 1: TEMPORAL NARRATIVE GENERATION
# ============================================================

print("\n" + "="*60)
print("APPROACH 1: LLM NARRATIVE GENERATION")
print("="*60)

# Create daily summaries that LLM can understand
daily_summary = []

for date in pd.date_range(df['date'].min(), df['date'].max(), freq='D'):
    day_events = df[df['date'] == date.date()]
    if len(day_events) > 0:
        summary = {
            'date': str(date.date()),
            'total_events': len(day_events),
            'users': day_events['username'].value_counts().head(3).to_dict(),
            'top_actions': day_events['eventName'].value_counts().head(5).to_dict(),
            'error_rate': float(day_events.get('errorCode', pd.Series()).notna().sum() / len(day_events) * 100) if 'errorCode' in day_events.columns else 0.0
        }
        daily_summary.append(summary)

# Find interesting days (>10k events)
interesting_days = [d for d in daily_summary if d['total_events'] > 10000]

print(f"\nFound {len(interesting_days)} anomalous days")
print("\nLLM PROMPT #1 (Temporal Narrative):")
print("-" * 60)

prompt1 = f"""You are a cloud security forensic analyst. Analyze this CloudTrail activity pattern:

BACKGROUND: This is from an intentionally vulnerable AWS CTF (Capture The Flag) challenge where credentials were deliberately leaked.

DAILY ACTIVITY SUMMARY (Top {len(interesting_days[:5])} anomalous days):
{json.dumps(interesting_days[:5], indent=2)}

Based on this pattern, answer:
1. What type of attack is this?
2. Is this manual or automated?
3. What was the attacker trying to achieve?

Focus on the spike in RunInstances attempts and high error rates."""

print(prompt1)
print("\n" + "="*60)

# ============================================================
# APPROACH 2: BEHAVIOR CLASSIFICATION
# ============================================================

print("\n" + "="*60)
print("APPROACH 2: USER BEHAVIOR INTERPRETATION")
print("="*60)

# Create user behavior profiles
user_profiles = {}

for user in ['Level5', 'Level6', 'backup']:
    if user in df['username'].values:
        user_df = df[df['username'] == user]
        duration_days = (user_df['eventTime'].max() - user_df['eventTime'].min()).days + 1
        profile = {
            'username': user,
            'first_seen': str(user_df['eventTime'].min()),
            'last_seen': str(user_df['eventTime'].max()),
            'total_events': int(len(user_df)),
            'unique_actions': int(user_df['eventName'].nunique()),
            'top_actions': {k: int(v) for k, v in user_df['eventName'].value_counts().head(5).to_dict().items()},
            'error_rate': float(user_df.get('errorCode', pd.Series()).notna().sum() / len(user_df) * 100) if 'errorCode' in user_df.columns else 0.0,
            'events_per_day': float(len(user_df) / duration_days)
        }
        user_profiles[user] = profile

print("\nLLM PROMPT #2 (User Behavior Comparison):")
print("-" * 60)

prompt2 = f"""Analyze these user behavior patterns from AWS CloudTrail:

{json.dumps(user_profiles, indent=2)}

Compare these users and explain:
1. Which user was doing reconnaissance vs exploitation?
2. Which users appear to be automated vs manual?
3. What is the relationship between Level5 and Level6?

Key insight: Level5 has only 39 events over 4 days, while Level6 has 900k+ events."""

print(prompt2)
print("\n" + "="*60)

# ============================================================
# APPROACH 3: ATTACK STAGE DETECTION
# ============================================================

print("\n" + "="*60)
print("APPROACH 3: ATTACK TIMELINE RECONSTRUCTION")
print("="*60)

# Create attack timeline
timeline_events = []

# Key dates
key_dates = [
    ('2017-02-12', 'backup'),
    ('2017-02-19', 'Level5'),
    ('2017-02-26', 'Level6'),
    ('2019-08-21', 'explosion')
]

for date_str, event_type in key_dates:
    date = pd.to_datetime(date_str).date()
    day_data = df[df['date'] == date]
    if len(day_data) > 0:
        timeline_events.append({
            'date': date_str,
            'event': event_type,
            'total_events': int(len(day_data)),
            'users': [str(u) for u in list(day_data['username'].value_counts().head(3).index)],
            'top_action': str(day_data['eventName'].value_counts().index[0]) if len(day_data) > 0 else None
        })

print("\nLLM PROMPT #3 (Attack Timeline):")
print("-" * 60)

prompt3 = f"""Reconstruct the attack timeline from these key events:

{json.dumps(timeline_events, indent=2)}

Additional context:
- Level5 credentials were found in Level4 challenge
- Level6 credentials discovered by Level5 reconnaissance
- August 2019 had 1.3 million events in 3 days
- 97.5% of August attempts failed (AWS rate limiting)

Write a forensic timeline of how these credentials were discovered and exploited."""

print(prompt3)
print("\n" + "="*60)

# ============================================================
# APPROACH 4: NATURAL LANGUAGE Q&A
# ============================================================

print("\n" + "="*60)
print("APPROACH 4: LLM AS FORENSIC ASSISTANT")
print("="*60)

# Pre-calculate statistics for LLM to reference
stats = {
    'total_events': int(len(df)),
    'date_range': f"{df['date'].min()} to {df['date'].max()}",
    'unique_users': int(df['username'].nunique()),
    'top_users': {k: int(v) for k, v in df['username'].value_counts().head(5).to_dict().items()},
    'top_actions': {k: int(v) for k, v in df['eventName'].value_counts().head(5).to_dict().items()},
    'august_2019_events': int(len(df[df['date'].astype(str).str.startswith('2019-08')])),
    'peak_day': str(df.groupby('date').size().idxmax()),
    'peak_day_events': int(df.groupby('date').size().max())
}

print("\nLLM Q&A CONTEXT:")
print("-" * 60)

context = f"""You are analyzing AWS CloudTrail logs from the flaws.cloud CTF dataset.

KEY STATISTICS:
{json.dumps(stats, indent=2)}

You can answer questions like:
- "What happened in August 2019?" → Mass automated exploitation, 1.3M events
- "How did the attack progress?" → Level5 recon → Level6 discovery → mass exploitation
- "Was this targeted?" → No, automated scanner found leaked credentials
"""

print(context)
print("\n" + "="*60)

# ============================================================
# SAVE ALL PROMPTS AND DATA FOR LLM INTEGRATION
# ============================================================

print("\n[2] Saving LLM-ready data structures...")

llm_data = {
    'daily_summary': daily_summary,
    'interesting_days': interesting_days,
    'user_profiles': user_profiles,
    'timeline_events': timeline_events,
    'statistics': stats,
    'prompts': {
        'narrative_generation': prompt1,
        'behavior_comparison': prompt2,
        'timeline_reconstruction': prompt3,
        'qa_context': context
    }
}

# Save to JSON for easy loading
output_file = 'llm_forensic_data.json'
with open(output_file, 'w') as f:
    json.dump(llm_data, f, indent=2)

print(f"✅ Saved to {output_file}")

# ============================================================
# CREATE SAMPLE Q&A EXAMPLES
# ============================================================

print("\n" + "="*60)
print("SAMPLE Q&A CONVERSATIONS")
print("="*60)

sample_questions = [
    "What happened on August 22, 2019?",
    "Compare Level5 and Level6 behavior",
    "Was this a targeted attack?",
    "Why did backup and Level6 have similar activity?",
    "Should we be worried about the flaws account?",
    "What type of attacker leaves this pattern?",
    "How long did the attacker have access?",
    "What was the attacker trying to accomplish?"
]

print("\nSample questions analysts can ask:")
for i, q in enumerate(sample_questions, 1):
    print(f"{i}. {q}")

# ============================================================
# THE KEY INSIGHT
# ============================================================

print("\n" + "="*60)
print("💡 WHY THIS WORKS")
print("="*60)

print("""
1. PRE-PROCESS: Convert 1.9M events → digestible summaries
2. CONTEXTUALIZE: Give LLM AWS/security context it lacks
3. FOCUS: Ask LLM to interpret patterns, not count events
4. CHUNK: Feed data in temporal chunks, not raw events

The LLM becomes valuable for:
✅ Writing forensic narratives
✅ Explaining technical events in plain English
✅ Comparing behavior patterns
✅ Answering "what happened?" questions

NOT for:
❌ Classifying individual events (25.6% confidence)
❌ Finding anomalies (use statistics)
❌ Counting or aggregating (use pandas)
""")

print("\n" + "="*60)
print("READY TO IMPLEMENT")
print("="*60)

print(f"""
Next steps:
1. Install OpenAI SDK: pip install openai
2. Set API key: export OPENAI_API_KEY='sk-...'
3. Run the interactive version: python llm_forensic_interactive.py
4. Or use the data file: {output_file}

This approach actually works because we're using LLMs
for narrative and explanation, not pattern detection.

Data structures saved to: {output_file}
Ready for GPT-4 integration!
""")

# ============================================================
# COST ESTIMATE
# ============================================================

print("\n" + "="*60)
print("💰 ESTIMATED COSTS (GPT-4)")
print("="*60)

# Token estimation
prompt1_tokens = len(prompt1.split()) * 1.3  # rough estimate
prompt2_tokens = len(prompt2.split()) * 1.3
prompt3_tokens = len(prompt3.split()) * 1.3
context_tokens = len(context.split()) * 1.3

total_input_tokens = prompt1_tokens + prompt2_tokens + prompt3_tokens + context_tokens
estimated_output_tokens = 2000  # generous estimate

# GPT-4 pricing (as of 2024)
input_cost = (total_input_tokens / 1000) * 0.03  # $0.03 per 1K tokens
output_cost = (estimated_output_tokens / 1000) * 0.06  # $0.06 per 1K tokens
total_cost = input_cost + output_cost

print(f"""
Estimated token usage:
- Input tokens: ~{int(total_input_tokens):,}
- Output tokens: ~{int(estimated_output_tokens):,}

Estimated cost per full analysis:
- Input: ${input_cost:.4f}
- Output: ${output_cost:.4f}
- Total: ${total_cost:.4f}

Cost for 100 analyses: ${total_cost * 100:.2f}

This is VERY affordable for enterprise forensics!
""")

print("="*60)
print("✅ ANALYSIS COMPLETE - Ready for LLM integration")
print("="*60)
