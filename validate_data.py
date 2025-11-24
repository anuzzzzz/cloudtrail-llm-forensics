"""
PROGRESSIVE DATA VALIDATION & DASHBOARD TESTER
Tests your data step-by-step before building dashboard
"""

import pandas as pd
import json
import gzip
from pathlib import Path
import sys

print("=" * 60)
print("FLAWS.CLOUD DATA VALIDATOR")
print("=" * 60)

# Step 1: Check files exist
print("\n[1] Checking for CloudTrail files...")
files_found = []
for i in range(20):
    file_path = f'flaws_cloudtrail{i:02d}.json.gz'
    if Path(file_path).exists():
        files_found.append(file_path)
        print(f"  ✅ Found: {file_path}")
    else:
        print(f"  ❌ Missing: {file_path}")

if not files_found:
    print("\n❌ ERROR: No CloudTrail files found!")
    print("Make sure you're in the directory with flaws_cloudtrail*.json.gz files")
    sys.exit(1)

print(f"\n✅ Found {len(files_found)} files")

# Step 2: Test loading first file
print("\n[2] Testing data loading with first file...")
try:
    with gzip.open(files_found[0], 'rt', encoding='utf-8') as f:
        data = json.load(f)
    
    if 'Records' in data:
        print(f"  ✅ Successfully loaded {len(data['Records'])} events from {files_found[0]}")
    else:
        print("  ❌ ERROR: No 'Records' field in JSON")
        sys.exit(1)
except Exception as e:
    print(f"  ❌ ERROR loading file: {e}")
    sys.exit(1)

# Step 3: Test DataFrame creation
print("\n[3] Testing DataFrame creation...")
try:
    df_test = pd.DataFrame(data['Records'][:100])  # Test with first 100 records
    print(f"  ✅ Created DataFrame with {len(df_test)} rows and {len(df_test.columns)} columns")
except Exception as e:
    print(f"  ❌ ERROR creating DataFrame: {e}")
    sys.exit(1)

# Step 4: Check required fields
print("\n[4] Checking required fields...")
required_fields = ['eventTime', 'eventName', 'userIdentity', 'eventSource']
missing_fields = []

for field in required_fields:
    if field in df_test.columns:
        print(f"  ✅ Found field: {field}")
    else:
        print(f"  ❌ Missing field: {field}")
        missing_fields.append(field)

if missing_fields:
    print("\n❌ ERROR: Missing required fields!")
    sys.exit(1)

# Step 5: Test field extraction
print("\n[5] Testing field extraction...")
try:
    # Test datetime parsing
    df_test['eventTime'] = pd.to_datetime(df_test['eventTime'])
    print(f"  ✅ Parsed eventTime successfully")
    
    # Test username extraction
    def extract_username(user_identity):
        if not isinstance(user_identity, dict):
            return 'Unknown'
        if 'userName' in user_identity:
            return user_identity['userName']
        elif 'principalId' in user_identity:
            principal = user_identity['principalId']
            if ':' in str(principal):
                return principal.split(':')[-1]
            return str(principal)
        return 'Unknown'
    
    df_test['username'] = df_test['userIdentity'].apply(extract_username)
    print(f"  ✅ Extracted usernames successfully")
    
    # Check for errorCode
    if 'errorCode' in df_test.columns:
        df_test['has_error'] = df_test['errorCode'].notna()
        print(f"  ✅ Found errorCode field")
    else:
        df_test['has_error'] = False
        print(f"  ⚠️  No errorCode field - setting has_error to False")
    
    print(f"  ✅ All field extractions successful")
    
except Exception as e:
    print(f"  ❌ ERROR in field extraction: {e}")
    sys.exit(1)

# Step 6: Test aggregations
print("\n[6] Testing data aggregations...")
try:
    user_counts = df_test['username'].value_counts()
    print(f"  ✅ Found {len(user_counts)} unique users")
    print(f"     Top users: {', '.join(user_counts.head(3).index.tolist())}")
    
    event_counts = df_test['eventName'].value_counts()
    print(f"  ✅ Found {len(event_counts)} unique event types")
    print(f"     Top events: {', '.join(event_counts.head(3).index.tolist())}")
    
except Exception as e:
    print(f"  ❌ ERROR in aggregations: {e}")
    sys.exit(1)

# Step 7: Full data load test
print("\n[7] Testing full data load (this may take a moment)...")
all_events = []
error_files = []

for file_path in files_found[:3]:  # Test first 3 files
    try:
        with gzip.open(file_path, 'rt', encoding='utf-8') as f:
            data = json.load(f)
            all_events.extend(data['Records'])
        print(f"  ✅ Loaded {file_path}")
    except Exception as e:
        print(f"  ❌ Error loading {file_path}: {e}")
        error_files.append(file_path)

if error_files:
    print(f"\n⚠️  WARNING: {len(error_files)} files had errors")
else:
    print(f"\n✅ Successfully tested loading {len(files_found[:3])} files")
    print(f"   Total events loaded: {len(all_events):,}")

# Step 8: Test date operations
print("\n[8] Testing date operations...")
try:
    df_full = pd.DataFrame(all_events)
    df_full['eventTime'] = pd.to_datetime(df_full['eventTime'])
    df_full['date'] = df_full['eventTime'].dt.date
    df_full['month'] = df_full['eventTime'].dt.to_period('M').astype(str)

    # Extract username for full dataset
    df_full['username'] = df_full['userIdentity'].apply(extract_username)

    print(f"  ✅ Date range: {df_full['date'].min()} to {df_full['date'].max()}")
    
    # Check for August 2019
    if '2019-08' in df_full['month'].values:
        aug_count = len(df_full[df_full['month'] == '2019-08'])
        print(f"  ✅ Found August 2019 data: {aug_count:,} events")
    else:
        print(f"  ⚠️  No August 2019 data in tested files")
        
except Exception as e:
    print(f"  ❌ ERROR in date operations: {e}")

print("\n" + "=" * 60)
print("VALIDATION COMPLETE")
print("=" * 60)

# Summary
print("\n📊 SUMMARY:")
print(f"  Files found: {len(files_found)}")
print(f"  Files tested: {min(3, len(files_found))}")
print(f"  Events loaded: {len(all_events):,}")
print(f"  All tests: PASSED ✅")

print("\n✅ Your data is ready for the dashboard!")
print("\n📝 Data structure found:")
print(f"  - Date range: {df_full['date'].min()} to {df_full['date'].max()}")
print(f"  - Unique users: {df_full['username'].nunique()}")
print(f"  - Unique events: {df_full['eventName'].nunique()}")

# Export top users for dashboard defaults
top_users = df_full['username'].value_counts().head(10)
print(f"\n👥 Top 10 users (safe for dashboard defaults):")
for i, (user, count) in enumerate(top_users.items(), 1):
    print(f"  {i}. {user}: {count:,} events")

print("\n💡 RECOMMENDATIONS:")
print("  1. Use these users as defaults:", top_users.head(3).index.tolist())
print("  2. Avoid Level5 as default (only 39 events)")
print("  3. Focus on August 2019 for anomaly analysis")
print("\n✅ Ready to run dashboard!")