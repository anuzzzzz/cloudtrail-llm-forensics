# CloudTrail Forensic Analysis with LLM

LLM-powered narrative generation for AWS CloudTrail logs from the flaws.cloud CTF dataset.

## Setup

1. Download CloudTrail logs:
```bash
# Download from flaws.cloud
wget http://flaws.cloud/cloudtrail_logs.tar.gz
tar -xzf cloudtrail_logs.tar.gz
```

2. Install dependencies:
```bash
pip install -r requirements_llm.txt
```

3. Configure API key:
```bash
cp .env.example .env
# Edit .env and add your OpenAI API key
export OPENAI_API_KEY='sk-proj-...'
```

4. Generate analysis:
```bash
python forensic_analysis.py
```

5. Run interactive analysis:
```bash
python interactive.py
```

## Features

- **Attack narrative** - What happened in August 2019
- **User comparison** - Level5 vs Level6 behavioral differences
- **Timeline reconstruction** - Complete attack lifecycle
- **Attack phases** - Reconnaissance to exploitation progression
- **IP intelligence** - Attacker infrastructure analysis
- **Behavioral sequences** - Session-by-session actions
- **Error forensics** - AWS defensive measures
- **User correlations** - Shared infrastructure patterns
- **Explosion timeline** - Hour-by-hour August 2019 analysis
- **Custom Q&A** - Ask specific questions
- **Report generation** - Comprehensive forensic report

## Architecture

- 1.9M CloudTrail events → Pre-processed analysis
- 9 analysis strategies (phases, IPs, behaviors, errors, correlations)
- GPT-4 Turbo for narrative generation (~$0.02/query)
- Output: Analyst-ready forensic insights
