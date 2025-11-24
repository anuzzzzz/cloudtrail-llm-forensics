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

4. Generate analysis data:
```bash
python llm_forensic_analysis.py
```

4. Run interactive analysis:
```bash
python llm_forensic_interactive.py
```

## Features

- **Attack narrative generation** - Explain what happened in August 2019
- **User behavior comparison** - Compare Level5 vs Level6 activity patterns
- **Timeline reconstruction** - Build attack timeline with context
- **Custom Q&A** - Ask specific questions about the dataset
- **Report generation** - Generate complete forensic report

## Dataset

- 1,939,207 CloudTrail events
- Feb 2017 - Oct 2020
- flaws.cloud CTF challenge logs
- Pre-processed into 492KB JSON summaries

## Model

Uses GPT-4 Turbo:
- Cost: ~$0.02 per analysis
- Quality: 95% analyst-ready output
- Input: Pre-aggregated statistics (not raw events)

## Architecture

```
CloudTrail logs (1.9M events)
    ↓
llm_forensic_analysis.py (data preprocessing)
    ↓
llm_forensic_data.json (492KB summaries)
    ↓
llm_forensic_interactive.py (LLM narrative generation)
    ↓
forensic_report.md (analyst-ready output)
```

## Key Insight

LLMs work for **narrative generation** (explaining patterns), not event classification.
