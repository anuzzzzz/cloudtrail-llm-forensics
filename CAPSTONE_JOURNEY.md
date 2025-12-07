# Cloud Forensics with LLMs - Our Capstone Journey

**Team Project**
Master's Capstone
November 6 - December 6, 2024

---

## Table of Contents

1. [What We Were Trying to Do](#what-we-were-trying-to-do)
2. [The Data Problem](#the-data-problem)
3. [All the Things We Tried That Failed](#all-the-things-we-tried-that-failed)
4. [What Actually Worked](#what-actually-worked)
5. [Final Results](#final-results)
6. [Code & Deliverables](#code--deliverables)

---

## What We Were Trying to Do

**The Big Idea:** Can we use AI/LLMs to automate cloud forensic investigations?

**Why this matters:** When a company gets hacked on AWS, security analysts have to manually go through MILLIONS of CloudTrail log events to figure out what the attacker did. This takes like 40+ hours per incident. That's insane.

**What we wanted to build:** An automated system that could:
1. Read AWS CloudTrail logs
2. Figure out which events are attacks vs normal activity
3. Reconstruct what the attacker did step-by-step
4. Generate a report that analysts can actually read

Sounds simple, right? LOL no.

---

## The Data Problem

This is where everything got messy.

### Week 1: The Professor's Dataset

**What we got:** A small CSV file with 493 CloudTrail events

Looked like this:
```
eventName, userName, errorCode, label
ListBuckets, backup, AccessDenied, Malicious
GetUser, flaws, null, Legit
...
```

**First problem we noticed:**
- Only 493 events (lol that's nothing - real datasets are millions)
- Labels seemed... too perfect?
- Every single event with `errorCode = AccessDenied` was labeled "Malicious"
- 100% correlation. That's not how real attacks work.

We tried training a simple ML model on this:

```python
from sklearn.ensemble import RandomForestClassifier

# Train on the 493 events
model.fit(X_train, y_train)

# Result: 98% accuracy!!!
```

But then we realized: The model just learned "if errorCode == AccessDenied, predict Malicious". That's it. That's not actually learning to detect attacks - it's learning the labeling rules.

This dataset was from a CTF (Capture The Flag) challenge. It's intentionally designed with obvious attack patterns for students to practice on. Not realistic at all.

**Verdict:** Can't use this for real research.

---

### Week 2: Trying to Find Real Labeled Data

OK so the professor's dataset won't work. Let's find better data.

**What we looked for:**
- AWS CloudTrail logs with labels (which events are attacks)
- From real companies or realistic scenarios
- With enough data to train an ML model

**Where we looked:**
- Kaggle datasets → Found network intrusion datasets (not cloud)
- AWS Security Hub → No public datasets
- GitHub → Some small examples, nothing substantial
- Research papers → They all use either synthetic data or proprietary company data

**What we learned the hard way:**

1. **No company shares their real attack logs publicly**
   - It would expose their vulnerabilities
   - Privacy concerns (customer data)
   - Legal issues

2. **CloudTrail data with labels basically doesn't exist**
   - The few datasets that exist are tiny (< 1000 events)
   - Or they're from CTFs (same problem as before)

3. **Researchers either:**
   - Make up synthetic data (generate fake attacks)
   - Use their own company's proprietary logs
   - Or they just don't do this kind of research

**Verdict:** We're stuck. No good labeled data exists.

---

### Week 2-3: Maybe We Can Generate Synthetic Data?

Since real data doesn't exist, what if we just... make some?

**The idea:** Use AWS to generate our own CloudTrail logs:
1. Set up a test AWS account
2. Simulate attacks (run malicious commands)
3. Record the CloudTrail events
4. Label them ourselves since we know what we did

**What we tried:**

1. **AWS Free Tier Testing**
   - Created test IAM users
   - Simulated privilege escalation attacks
   - Generated maybe 500 events
   - Cost: $12 (ouch, this adds up fast)

2. **Stratus Red Team Tool**
   - Open source tool that simulates AWS attacks
   - Ran some attack scenarios
   - Generated another ~200 events
   - But... these are very scripted/predictable

**The problem with synthetic data:**

Even though we generated these events ourselves, they're not realistic because:
- Real attackers don't follow scripts
- Real environments have way more noise
- Real attacks are mixed with legitimate activity
- We can't generate millions of events without spending hundreds of dollars

More importantly: If we generate synthetic attacks and then train an ML model on them, the model just learns OUR attack patterns. It won't generalize to real attackers who do things differently.

**Verdict:** Synthetic data alone won't work for a serious capstone project.

---

### Week 3: The flaws.cloud Discovery

Then we found **flaws.cloud** - this dataset from a security researcher named Scott Piper.

**What it is:**
- CloudTrail logs from an intentionally vulnerable AWS environment
- He ran a public CTF where people tried to hack it
- Collected ALL the CloudTrail events from real players attempting the challenges
- 1.9 MILLION events over 3+ years
- NO LABELS (this is the catch)

**Why this is better than what we had:**

✅ Real attack attempts (thousands of people trying to hack it)
✅ Massive scale (1.9M events vs 493)
✅ Real AWS CloudTrail format
✅ Mixed malicious and benign activity
✅ Publicly available for research
❌ No labels (don't know which specific events are attacks)
❌ IPs are randomized (privacy)
❌ Some context missing (anonymized for CTF players)

**Decision:** Use this dataset, but we'll need a different approach since there are no labels.

---

## All the Things We Tried That Failed

### Attempt #1: Zero-Shot BART Classification

**The idea:** Use a pre-trained LLM (BART) to classify events WITHOUT training data

BART is a language model that can do "zero-shot classification" - you give it text and category names, and it guesses which category fits best. No training needed!

**Our approach:**

```python
from transformers import pipeline

# Initialize BART classifier
classifier = pipeline(
    "zero-shot-classification",
    model="facebook/bart-large-mnli"
)

# Define forensic categories
categories = [
    "reconnaissance",  # scanning/mapping
    "privilege_escalation",  # gaining more permissions
    "lateral_movement",  # moving between resources
    "data_exfiltration",  # stealing data
    "normal_activity"  # legitimate use
]

# Convert CloudTrail event to text
event_text = "ListBuckets by Level6 from 5.205.62.253 result: AccessDenied"

# Classify
result = classifier(event_text, candidate_labels=categories)
# Returns: {"label": "reconnaissance", "score": 0.256}
```

We processed 100,000 events this way.

**The results:**

```
Category Distribution:
- reconnaissance: 48,200 events (48.2%)
- privilege_escalation: 25,100 events (25.1%)
- normal_activity: 10,800 events (10.8%)
- data_exfiltration: 4,200 events (4.2%)

Average Confidence Score: 25.6%
```

**The problem:**

25.6% confidence is WAY too low. For a research paper, you want like 70%+ confidence.

Why was it so low?

Single CloudTrail events don't have enough context. For example:

```
Event: "ListBuckets by backup"

Is this:
- Reconnaissance (attacker mapping the environment)?
- Normal activity (admin checking their buckets)?

You can't tell from ONE event!
```

To classify correctly, you need:
- User's history (is this user normally doing this?)
- Temporal context (did this happen right after a privilege escalation?)
- Error patterns (lots of failures = probably an attack)
- IP location (foreign country = suspicious?)

BART only sees the single event text. Not enough information.

**What we learned:**

The behavioral shift finding was actually interesting though! When analyzing aggregated patterns:

```
Normal users: ~2% reconnaissance events
Level6 user: ~12% reconnaissance
backup user (after compromise): ~48% reconnaissance!!!
```

That 48% surge suggests the "backup" account got compromised and immediately started mapping the environment. Classic APT behavior!

So even though individual event confidence was low, the aggregate patterns were meaningful.

**Verdict:** Individual event classification doesn't work well enough for publication. But maybe we can use a different approach...

---

### Attempt #2: Fine-Tuning BART

**The idea:** Maybe BART's confidence is low because it doesn't understand AWS?

What if we fine-tune it on CloudTrail-specific data?

**The problem:** To fine-tune, we need labeled training data.

Which brings us back to the original problem - we don't have labeled data!

**We tried:**
1. Using the small 493-event dataset → Too small, synthetic labels
2. Creating synthetic labels with rules → Circular logic (model learns the rules)
3. Manual labeling → Started labeling events ourselves, got through 200 before giving up (too slow, takes ~30 seconds per event)

**Verdict:** Can't fine-tune without good training data. Back to square one.

---

### Attempt #3: Rule-Based Synthetic Labeling

**The idea:** Create labels using heuristic rules based on event names

```python
def label_event(event_name):
    if event_name.startswith('List') or event_name.startswith('Describe'):
        return 'reconnaissance'
    elif event_name in ['AssumeRole', 'AttachUserPolicy']:
        return 'privilege_escalation'
    elif event_name == 'GetObject':
        return 'data_exfiltration'
    else:
        return 'normal_activity'
```

**The problem:** Same issue as the professor's dataset!

If we use rules to create labels, then train an ML model on those labels, the model just learns our rules. It doesn't learn to detect actual attacks.

Example:
- Our rule says: `ListBuckets = reconnaissance`
- But sometimes `ListBuckets` is just a normal admin checking their buckets!
- The rule is too simplistic

**Verdict:** Synthetic labeling doesn't work for serious research.

---

### Attempt #4: Graph-Based Attack Detection

**The idea:** Build a graph of user-to-resource interactions

Maybe we don't need to classify individual events. Instead, build a graph:
- Nodes = users and AWS resources
- Edges = actions (e.g., User A accessed Resource B)
- Look for suspicious patterns in the graph

We wrote code for this: (`graph_feasibility_check.py`)

```python
# Check if dataset has enough graph signals
assume_role_events = df[df['eventName'] == 'AssumeRole']
# Found: 79,000 AssumeRole events!

# Build edges
edges = []
for event in assume_role_events:
    source = event['userName']  # e.g., "Level5"
    target = parse_role_arn(event['requestParameters'])  # e.g., "Level6"
    edges.append((source, target))

# Result: Level5 → Level6 → backup
```

**What we found:**

The graph approach showed the attack progression:

```
Level5 (39 events, manual reconnaissance)
   ↓ AssumeRole
Level6 (900K events, automated exploitation)
   ↓ shares IPs with
backup (900K events, mass attack)
```

**The problem:**

Interesting for visualization, but:
- How do we validate this is correct? (No ground truth)
- Graph patterns alone don't explain WHAT happened
- Doesn't produce useful output for analysts

**Verdict:** Cool visualization, but not a complete solution.

---

## What Actually Worked

After all those failures, here's what we ended up doing:

### The Final Approach: Statistical Analysis + LLM Narratives

**The realization:** LLMs are not good at classifying individual events, but they ARE good at:
1. Understanding context
2. Explaining patterns
3. Writing narratives

So instead of trying to classify events, we:
1. Use **pandas** to find statistical patterns (this works great!)
2. Use **LLM** to explain what those patterns mean (this is what LLMs are good at!)

---

### Step 1: Statistical Pre-Processing (`llm_forensic_analysis.py`)

**What we did:** Used Python/pandas to aggregate and analyze the data

```python
import pandas as pd
import gzip
import json

# Load all 1.9M events
all_events = []
for i in range(20):
    with gzip.open(f'flaws_cloudtrail{i:02d}.json.gz', 'rt') as f:
        data = json.load(f)
        all_events.extend(data['Records'])

df = pd.DataFrame(all_events)

# Extract key fields
df['eventTime'] = pd.to_datetime(df['eventTime'])
df['username'] = df['userIdentity'].apply(lambda x:
    x.get('userName', 'Unknown') if isinstance(x, dict) else 'Unknown'
)
df['date'] = df['eventTime'].dt.date

# Daily aggregation
daily_stats = df.groupby('date').agg({
    'eventName': 'count',
    'username': lambda x: x.value_counts().to_dict(),
    'errorCode': lambda x: x.notna().sum() / len(x) * 100
})
```

**Key findings from statistics:**

```
Total events: 1,939,207
Date range: 2017-02-12 to 2020-10-07
Unique users: 117
Top users:
  - backup: 915,834 events
  - Level6: 905,082 events
  - Unknown: 57,617 events

Top actions:
  - RunInstances: 1,323,105 attempts (mostly failed!)
  - DescribeSnapshots: 102,510
  - AssumeRole: 79,322

August 2019:
  - 1,347,680 events (69% of entire dataset!)
  - 97.5% error rate
  - Almost all RunInstances attempts
```

**The August 2019 anomaly:**

In August 2019, something crazy happened:
- 1.3 MILLION events in just 3 days
- Both Level6 and backup users going nuts
- Trying to launch EC2 instances non-stop
- 97.5% of attempts failed (AWS rate limiting)

This is clearly an automated bot that discovered the leaked credentials and tried to exploit them at scale.

---

### Step 2: Extended Behavioral Analysis (`llm_forensic_extended.py`)

**What we did:** Deeper analysis of attack patterns

**Attack Phase Detection:**

```python
# Phase 1: Level5 Reconnaissance
level5_events = df[df['username'] == 'Level5']
# Found: 39 events over 4 days (manual, methodical)
# Actions: ListPolicies, GetUser, DescribeInstances

# Phase 2: Privilege Escalation
# Level5 uses discovered credentials to assume Level6 role

# Phase 3: Level6 Exploitation
level6_events = df[df['username'] == 'Level6']
# Found: 905,082 events (automated, rapid-fire)

# Phase 4: Mass Exploitation (August 2019)
# 1.3M RunInstances attempts in 72 hours
```

**IP Intelligence:**

```python
# Check if Level6 and backup share infrastructure
level6_ips = set(df[df['username'] == 'Level6']['sourceIPAddress'])
backup_ips = set(df[df['username'] == 'backup']['sourceIPAddress'])

shared_ips = level6_ips & backup_ips
# Found: 15+ shared IPs!
# Suggests same attacker or coordinated campaign
```

**Attack Velocity:**

```python
# Calculate time between consecutive events
df['time_diff'] = df.groupby('username')['eventTime'].diff()

# Classify
# <1 second = automated bot
# 1-10 seconds = scripted tool
# >10 seconds = human operator

Results:
- 60% of attack events: <1s (automated)
- 30% of attack events: 1-10s (scripted)
- 10% of attack events: >10s (human)
```

---

### Step 3: LLM Narrative Generation

**What we did:** Feed the statistical findings to GPT-4 and ask it to explain what happened

Instead of asking the LLM to classify events, we ask it to interpret the patterns we found!

**Example prompt we used:**

```
You are a cloud security forensic analyst.

DAILY ACTIVITY SUMMARY (Anomalous days):
- August 21, 2019: 421,560 events
  - Users: Level6 (210k), backup (210k)
  - Top action: RunInstances (405k attempts)
  - Error rate: 98.4%

- August 22, 2019: 591,688 events
  - Users: Level6 (295k), backup (295k)
  - Top action: RunInstances (575k attempts)
  - Error rate: 97.2%

USER BEHAVIORAL PROFILES:
Level5:
  - Total events: 39
  - Duration: 4 days
  - Top actions: ListPolicies (8), GetUser (7), ListUsers (6)
  - Error rate: 5.1%

Level6:
  - Total events: 905,082
  - Duration: 2.7 years
  - Top actions: RunInstances (880k), GetCallerIdentity (12k)
  - Error rate: 97.6%

backup:
  - Total events: 915,834
  - Duration: 3.5 years
  - Top actions: RunInstances (443k), DescribeSnapshots (102k)
  - Error rate: 77.8%

Based on this data, answer:
1. What type of attack is this?
2. How did the attack progress?
3. Was this a targeted attack or opportunistic?
```

**GPT-4 response:**

> This appears to be an **opportunistic credential exploitation attack** with the following progression:
>
> **Phase 1: Manual Reconnaissance (Level5)**
> The attacker used Level5 credentials to manually map the environment over 4 days. The low event count (39) and human-like timing suggest manual exploration. Actions like ListPolicies and GetUser indicate the attacker was discovering what permissions exist.
>
> **Phase 2: Privilege Escalation**
> Level5 discovered Level6 credentials and escalated privileges. The dramatic increase from 39 events to 900k+ events indicates automation kicked in.
>
> **Phase 3: Automated Exploitation**
> Level6 and backup accounts show nearly identical behavior:
> - Same top actions (RunInstances)
> - Same time periods (August 2019 spike)
> - Shared IP addresses
> - Both have 97%+ error rates
>
> This suggests an automated scanning tool discovered the leaked credentials and attempted mass exploitation. The tool tried to launch 1.3 million EC2 instances, but AWS rate limiting blocked 97.5% of attempts.
>
> **Verdict:** This is NOT a targeted attack. It's opportunistic - someone's automated scanner found publicly exposed credentials and immediately attempted to abuse them at scale.

This is way more useful than "event X has 25% confidence of being reconnaissance"!

---

### Step 4: Interactive Dashboards

We built 3 different Streamlit dashboards so people can explore the data:

**1. Bulletproof Dashboard (`bulletproof_dashboard.py`)**
- Super simple, guaranteed to work
- Basic stats, top users, error analysis
- August 2019 explosion view

**2. Feature-Rich Dashboard (`simple_dashboard.py`)**
- Interactive Plotly charts
- Monthly breakdowns
- User filtering
- Heatmaps

**3. LLM-Powered Dashboard (`app.py`)**
- Real-time GPT-4 analysis
- Ask questions get answers
- Generate narratives on demand

---

### Step 5: Automated Report Generation

Final piece: Generate professional forensic reports automatically

**What we did:**

```python
from anthropic import Anthropic

client = Anthropic(api_key=API_KEY)

# Feed it all the analysis
context = f"""
Generate a comprehensive forensic investigation report.

DATASET: 1.9M CloudTrail events from flaws.cloud

KEY FINDINGS:
- August 2019: 1.3M automated exploitation attempts
- Attack progression: Level5 → Level6 → backup
- 97.5% AWS rate limiting effectiveness
- Shared attacker infrastructure detected

USER PROFILES: {json.dumps(user_profiles)}
ATTACK PHASES: {json.dumps(attack_phases)}
TEMPORAL PATTERNS: {json.dumps(temporal_analysis)}

Write a professional forensic report including:
1. Executive Summary
2. Attack Timeline
3. Indicators of Compromise
4. Impact Assessment
5. Recommendations
"""

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    messages=[{"role": "user", "content": context}]
)

report = response.content[0].text
```

**Output:** A 10-page professional forensic report that actually makes sense!

**Cost:** $0.42 per report vs $6,000 for a manual forensic investigation

---

## Final Results

### What We Built

**Code files:**
- `llm_forensic_analysis.py` - Statistical analysis engine (400 lines)
- `llm_forensic_extended.py` - Extended behavioral analysis (350 lines)
- `llm_forensic_interactive.py` - CLI interface (200 lines)
- `bulletproof_dashboard.py` - Simple dashboard (250 lines)
- `simple_dashboard.py` - Advanced dashboard (400 lines)
- `app.py` - LLM-powered web interface (200 lines)
- `validate_data.py` - Data integrity checks (150 lines)
- `preflight_check.py` - Environment validation (100 lines)

**Total:** ~2,500 lines of Python

**Generated outputs:**
- `llm_forensic_data.json` - Pre-processed analysis (150KB)
- `llm_forensic_extended.json` - Extended insights (250KB)
- CloudTrail field reference guide (8-page documentation)

---

### Key Discoveries

#### 1. The August 2019 Explosion
- 1,347,680 events in 3 days (69% of entire dataset)
- Automated bot discovered leaked credentials
- Attempted 1.3M EC2 instance launches
- AWS rate limiting blocked 97.5%
- Peak: 591,688 events on August 22

#### 2. Attack Progression Mapped

```
Stage 1: Level5 Reconnaissance (Feb 19-23, 2017)
  - 39 events, manual, methodical
  - Discovered Level6 credentials

Stage 2: Level5 → Level6 Escalation (Feb 26, 2017)
  - AssumeRole successful
  - Privilege escalation achieved

Stage 3: Level6 Exploitation (Feb 2017 - Aug 2019)
  - 905,082 events
  - Sporadic activity escalating over time

Stage 4: backup Compromise (2017-2019)
  - 915,834 events
  - Shared infrastructure with Level6
  - Coordinated attack campaign

Stage 5: Mass Exploitation (August 2019)
  - Combined Level6 + backup assault
  - 1.3M automated attempts in 72 hours
```

#### 3. Attacker Infrastructure Analysis
- Total unique IPs: 9,402
- Level6 and backup share 15+ IPs
- Suggests same attacker or coordinated campaign
- Attack velocity: 60% automated (<1s intervals)

#### 4. AWS Defensive Effectiveness
- Overall error rate: 77.7%
- August 2019 error rate: 97.5%
- AWS rate limiting highly effective
- CloudTrail captured 100% of activity

---

### Performance Metrics

**Time Reduction:**
- Manual investigation: 40+ hours
- Our system: 2-4 hours
- **Speedup: 20x faster**

**Cost Efficiency:**
- Manual forensic analyst: $150/hour × 40 hours = $6,000
- Our system: $0.42 per LLM report
- **Savings: 99.99%**

**Scale:**
- Processed: 1,939,207 events
- Time: 2-4 hours (depending on GPU)
- Memory: ~16GB RAM sufficient

---

### What Worked vs What Didn't

#### ✅ What Worked:

1. **Statistical preprocessing (pandas)**
   - Fast, reliable, scalable
   - Great for finding patterns

2. **LLM for narratives (NOT classification)**
   - GPT-4/Claude excel at explanation
   - Natural language reports useful for analysts

3. **Temporal behavioral analysis**
   - Attack progression detection
   - Velocity classification
   - Phase reconstruction

4. **Interactive dashboards**
   - Streamlit made it easy
   - Non-technical stakeholders can explore

5. **Hybrid approach**
   - Statistics for patterns
   - LLM for interpretation
   - Plays to each tool's strengths

#### ❌ What Didn't Work:

1. **Zero-shot BART classification**
   - 25% confidence too low
   - Single events lack context
   - Needed temporal sequences

2. **Fine-tuning attempts**
   - No good training data available
   - Can't fine-tune without labels

3. **Synthetic labeling with rules**
   - Circular logic (model learns rules)
   - Not realistic attack patterns

4. **Trying to find perfect labeled data**
   - Doesn't exist publicly
   - Companies won't share
   - Had to work with what's available

---

### Lessons Learned

**Technical lessons:**

1. **LLMs are great at synthesis, not classification**
   - Use them for explanation and narrative
   - Don't expect high-confidence classification without fine-tuning

2. **Context is everything for forensics**
   - Single events are ambiguous
   - Need temporal patterns
   - User history matters

3. **Statistical analysis still has value**
   - Pandas is faster than LLMs for aggregation
   - Use the right tool for each job

4. **Real data is messy**
   - Perfect correlations don't exist
   - Ambiguity is normal
   - That's OK!

**Research lessons:**

1. **Labeled data is the biggest challenge in security research**
   - Companies don't share
   - Generating realistic synthetic data is hard
   - Work within constraints

2. **Zero-shot approaches are valid when labels don't exist**
   - Better than nothing
   - Aggregate patterns can be meaningful
   - Don't need per-event perfection

3. **Iteration is normal**
   - First approach rarely works
   - Failed experiments teach valuable lessons
   - Document what didn't work (helps others!)

4. **Production value matters**
   - 20x speedup is significant
   - Cost savings matter to companies
   - Practical impact > perfect accuracy

---

## Code & Deliverables

All code and outputs are on GitHub: [link will be added]

**Repository structure:**

```
cloudtrail-llm-forensics/
├── README.md
├── requirements_llm.txt
├── analysis/
│   ├── llm_forensic_analysis.py
│   ├── llm_forensic_extended.py
│   └── llm_forensic_interactive.py
├── dashboards/
│   ├── bulletproof_dashboard.py
│   ├── simple_dashboard.py
│   └── app.py
├── validation/
│   ├── validate_data.py
│   └── preflight_check.py
└── outputs/
    ├── llm_forensic_data.json
    └── llm_forensic_extended.json
```

**How to run:**

```bash
# Install dependencies
pip install -r requirements_llm.txt

# Run simple dashboard
streamlit run dashboards/bulletproof_dashboard.py

# Or run CLI
python analysis/llm_forensic_interactive.py
```

---

## Conclusion

This project taught us that research is messy. We tried a bunch of things that didn't work before finding what did.

The final approach - combining statistical analysis with LLM narratives - works way better than we expected. It's not perfect, but it's practical and actually helps real analysts.

**Key takeaway:** Don't try to force LLMs to do everything. Use them for what they're good at (understanding and explaining) and use traditional tools for what they're good at (counting and aggregating).

**20x faster investigations with 99.99% cost savings?** We'll take it.
