#!/usr/bin/env python3
"""Check actual API response data"""
import sys, os
os.environ['PYTHONIOENCODING'] = 'utf-8'
import requests
import json

BASE_URL = "http://localhost:5000"

print("\nAPI Response Data Check\n" + "="*80)

# Test 1: Public endpoint
print("\n[1] Public Router Status")
try:
    resp = requests.get(f"{BASE_URL}/api/router-status/public", timeout=5)
    if resp.status_code == 200:
        data = resp.json()
        print(f"Response: {json.dumps(data, indent=2)}")
    else:
        print(f"Status: {resp.status_code}")
except Exception as e:
    print(f"Error: {e}")

print("\n" + "="*80)
