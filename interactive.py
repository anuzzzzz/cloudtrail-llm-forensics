#!/usr/bin/env python3
"""Interactive LLM forensic assistant"""

import json
import os
import sys
import openai
from dotenv import load_dotenv

# Load environment configuration
load_dotenv()
api_key = os.getenv('OPENAI_API_KEY')
if not api_key:
    print("Error: OPENAI_API_KEY not set")
    sys.exit(1)

# Load analysis data
try:
    with open('forensic_analysis.json', 'r') as f:
        data = json.load(f)
except FileNotFoundError:
    print("Error: forensic_analysis.json not found")
    print("Run: python forensic_analysis.py")
    sys.exit(1)

def call_llm(prompt, model="gpt-4-turbo"):
    """Send prompt to OpenAI API"""
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

def ask_custom_question(question):
    """Answer custom questions about the dataset"""
    context = f"""Dataset statistics:
{json.dumps(data['statistics'], indent=2)}

User profiles:
{json.dumps(data['user_profiles'], indent=2)}

Question: {question}

Provide a concise, factual answer."""

    return call_llm(context)

def generate_report():
    """Generate comprehensive forensic report"""
    narrative = call_llm(data['prompts']['narrative'])
    timeline = call_llm(data['prompts']['timeline'])
    comparison = call_llm(data['prompts']['user_comparison'])

    report = f"""# CloudTrail Forensic Analysis Report

## Attack Narrative
{narrative}

## Timeline Reconstruction
{timeline}

## User Behavior Analysis
{comparison}

## Key Statistics
{json.dumps(data['statistics'], indent=2)}
"""

    with open('forensic_report.md', 'w') as f:
        f.write(report)

    return "Report saved to forensic_report.md"

def main():
    """Interactive menu"""
    menu_options = {
        '1': ('Attack narrative', data['prompts']['narrative']),
        '2': ('User comparison', data['prompts']['user_comparison']),
        '3': ('Timeline reconstruction', data['prompts']['timeline']),
        '4': ('Attack phases', data['prompts']['attack_phases']),
        '5': ('IP intelligence', data['prompts']['ip_intelligence']),
        '6': ('Behavioral sequences', data['prompts']['behavioral_sequences']),
        '7': ('Error forensics', data['prompts']['error_forensics']),
        '8': ('User correlations', data['prompts']['correlations']),
        '9': ('Explosion timeline', data['prompts']['explosion_timeline']),
    }

    while True:
        print("\n" + "="*60)
        print("CloudTrail Forensic Analysis")
        print("="*60)

        for key, (name, _) in menu_options.items():
            print(f"{key}. {name}")

        print("\n10. Ask custom question")
        print("11. Generate full report")
        print("12. View statistics")
        print("0. Exit")

        choice = input("\nChoice: ").strip()

        if choice == '0':
            break
        elif choice in menu_options:
            print(f"\nAnalyzing {menu_options[choice][0]}...")
            result = call_llm(menu_options[choice][1])
            print(f"\n{result}\n")
        elif choice == '10':
            question = input("\nQuestion: ").strip()
            if question:
                result = ask_custom_question(question)
                print(f"\n{result}\n")
        elif choice == '11':
            print("\nGenerating report (3 API calls)...")
            result = generate_report()
            print(f"\n{result}\n")
        elif choice == '12':
            print(f"\n{json.dumps(data['statistics'], indent=2)}\n")
        else:
            print("Invalid choice")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
