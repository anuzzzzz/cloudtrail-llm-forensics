#!/usr/bin/env python3
"""LLM-powered CloudTrail forensic analysis"""

import json
import os
import sys
import openai

# Load configuration
from dotenv import load_dotenv
load_dotenv()

api_key = os.getenv('OPENAI_API_KEY')
if not api_key:
    print("Error: OPENAI_API_KEY not set")
    print("Set it in .env file or export OPENAI_API_KEY='sk-...'")
    sys.exit(1)

with open('llm_forensic_data.json', 'r') as f:
    data = json.load(f)

def call_llm(prompt, model="gpt-4-turbo"):
    """Call OpenAI API"""
    client = openai.OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a cloud security forensic analyst."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.7,
        max_tokens=1000
    )
    return response.choices[0].message.content

def analyze_narrative():
    """Generate attack narrative"""
    return call_llm(data['prompts']['narrative_generation'])

def compare_users():
    """Compare user behaviors"""
    return call_llm(data['prompts']['behavior_comparison'])

def reconstruct_timeline():
    """Reconstruct attack timeline"""
    return call_llm(data['prompts']['timeline_reconstruction'])

def ask_question(question):
    """Ask custom question"""
    prompt = f"{data['prompts']['qa_context']}\n\nQUESTION: {question}\n\nProvide a concise answer."
    return call_llm(prompt)

def generate_report():
    """Generate full forensic report"""
    narrative = analyze_narrative()
    behavior = compare_users()
    timeline = reconstruct_timeline()

    report = f"""# CloudTrail Forensic Analysis Report

## Attack Narrative
{narrative}

## User Behavior Analysis
{behavior}

## Timeline Reconstruction
{timeline}

## Statistics
{json.dumps(data['statistics'], indent=2)}
"""

    with open('forensic_report.md', 'w') as f:
        f.write(report)

    return report

def load_extended_analysis():
    """Load extended analysis if available"""
    try:
        with open('llm_forensic_extended.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

extended_data = load_extended_analysis()

def analyze_attack_phases():
    """Analyze distinct attack phases"""
    if not extended_data:
        print("Run llm_forensic_extended.py first")
        return
    return call_llm(extended_data['prompts']['attack_phases'])

def analyze_ip_intelligence():
    """Analyze IP patterns"""
    if not extended_data:
        print("Run llm_forensic_extended.py first")
        return
    return call_llm(extended_data['prompts']['ip_intelligence'])

def analyze_behavioral_sequences():
    """Analyze user behavior sequences"""
    if not extended_data:
        print("Run llm_forensic_extended.py first")
        return
    return call_llm(extended_data['prompts']['behavioral_sequences'])

def analyze_error_patterns():
    """Analyze error forensics"""
    if not extended_data:
        print("Run llm_forensic_extended.py first")
        return
    return call_llm(extended_data['prompts']['error_forensics'])

def analyze_correlations():
    """Analyze user correlations"""
    if not extended_data:
        print("Run llm_forensic_extended.py first")
        return
    return call_llm(extended_data['prompts']['correlation_analysis'])

def analyze_explosion_timeline():
    """Analyze hourly explosion timeline"""
    if not extended_data:
        print("Run llm_forensic_extended.py first")
        return
    return call_llm(extended_data['prompts']['explosion_timeline'])

def main():
    """Interactive CLI"""
    while True:
        print("\n" + "="*60)
        print("CloudTrail Forensic Analysis")
        print("="*60)
        print("Basic Analysis:")
        print("1. Analyze attack narrative")
        print("2. Compare user behaviors")
        print("3. Reconstruct timeline")
        print("4. Ask custom question")
        print("5. Generate full report")
        print("6. View statistics")

        if extended_data:
            print("\nExtended Analysis:")
            print("7. Attack phases")
            print("8. IP intelligence")
            print("9. Behavioral sequences")
            print("10. Error forensics")
            print("11. User correlations")
            print("12. Explosion timeline")

        print("\n0. Exit")

        choice = input("\nChoice: ").strip()

        if choice == '1':
            print("\n" + analyze_narrative())
        elif choice == '2':
            print("\n" + compare_users())
        elif choice == '3':
            print("\n" + reconstruct_timeline())
        elif choice == '4':
            q = input("\nQuestion: ").strip()
            if q:
                print("\n" + ask_question(q))
        elif choice == '5':
            print("\nGenerating report...")
            generate_report()
            print("Saved to forensic_report.md")
        elif choice == '6':
            print("\n" + json.dumps(data['statistics'], indent=2))
        elif choice == '7' and extended_data:
            print("\n" + analyze_attack_phases())
        elif choice == '8' and extended_data:
            print("\n" + analyze_ip_intelligence())
        elif choice == '9' and extended_data:
            print("\n" + analyze_behavioral_sequences())
        elif choice == '10' and extended_data:
            print("\n" + analyze_error_patterns())
        elif choice == '11' and extended_data:
            print("\n" + analyze_correlations())
        elif choice == '12' and extended_data:
            print("\n" + analyze_explosion_timeline())
        elif choice == '0':
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
