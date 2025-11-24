
#!/usr/bin/env python3
"""
PRE-FLIGHT CHECK
Run this BEFORE the dashboard to ensure everything works
"""

import sys
import subprocess

print("=" * 60)
print("FLAWS DASHBOARD PRE-FLIGHT CHECK")
print("=" * 60)

# Check Python version
print("\n[1] Checking Python version...")
py_version = sys.version_info
print(f"    Python {py_version.major}.{py_version.minor}.{py_version.micro}")
if py_version.major >= 3 and py_version.minor >= 8:
    print("    ✅ Python version OK")
else:
    print("    ⚠️  Python 3.8+ recommended")

# Check imports
print("\n[2] Checking required libraries...")

libraries = {
    'streamlit': 'Dashboard framework',
    'pandas': 'Data processing',
    'json': 'JSON parsing (built-in)',
    'gzip': 'File decompression (built-in)',
    'pathlib': 'File paths (built-in)'
}

missing = []
for lib, desc in libraries.items():
    try:
        __import__(lib)
        print(f"    ✅ {lib:12s} - {desc}")
    except ImportError:
        print(f"    ❌ {lib:12s} - {desc} [MISSING]")
        missing.append(lib)

if missing:
    print(f"\n❌ Missing libraries: {', '.join(missing)}")
    print("   Run: pip install", ' '.join([m for m in missing if m not in ['json', 'gzip', 'pathlib']]))
    sys.exit(1)

# Check for CloudTrail files
print("\n[3] Checking for CloudTrail files...")
from pathlib import Path

files_found = 0
for i in range(20):
    if Path(f'flaws_cloudtrail{i:02d}.json.gz').exists():
        files_found += 1

if files_found == 0:
    print("    ❌ No CloudTrail files found!")
    print("    Make sure you're in the right directory")
    sys.exit(1)
else:
    print(f"    ✅ Found {files_found} CloudTrail files")

# Test minimal data load
print("\n[4] Testing data loading...")
try:
    import gzip
    import json
    
    test_file = f'flaws_cloudtrail00.json.gz'
    if Path(test_file).exists():
        with gzip.open(test_file, 'rt', encoding='utf-8') as f:
            data = json.load(f)
        if 'Records' in data:
            print(f"    ✅ Successfully loaded test file")
            print(f"    Found {len(data['Records'])} events")
        else:
            print("    ❌ Invalid data structure")
            sys.exit(1)
except Exception as e:
    print(f"    ❌ Error loading data: {e}")
    sys.exit(1)

# Check Streamlit installation
print("\n[5] Checking Streamlit...")
try:
    import streamlit as st
    st_version = st.__version__
    print(f"    ✅ Streamlit version: {st_version}")
except Exception as e:
    print(f"    ❌ Streamlit issue: {e}")
    sys.exit(1)

# Final recommendations
print("\n" + "=" * 60)
print("✅ ALL CHECKS PASSED!")
print("=" * 60)

print("\n📊 RECOMMENDED DASHBOARD ORDER:")
print("  1. First try:  python bulletproof_dashboard.py")
print("     (Simplest, guaranteed to work)")
print("")
print("  2. If that works: streamlit run bulletproof_dashboard.py")
print("     (Full Streamlit interface)")
print("")
print("  3. Advanced: streamlit run simple_dashboard.py")
print("     (More features, might have issues)")

print("\n💡 TIP: Start with bulletproof_dashboard.py")
print("        It's designed to handle all edge cases!")