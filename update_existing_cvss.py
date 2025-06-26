#!/usr/bin/env python3

import os
import sys
import requests
import json

def update_existing_cvss_vectors():
    """Update existing M365 findings to use proper CVSS 3.1 vectors"""
    
    print("=== Updating Existing M365 Findings CVSS Vectors ===")
    
    # Load configuration
    sys.path.append(os.path.join(os.path.dirname(__file__), 'conf'))
    import conf
    
    api_url = conf.sysreptorAPIUrl
    headers = {
        'Authorization': conf.sysreptorAPI.replace('Authorization: ', ''),
        'Content-Type': 'application/json'
    }
    project_id = "0e2f7b0f-b1aa-4957-9b3c-43fc5dee9bf3"
    
    # CVSS mapping
    cvss_mapping = {
        'critical': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'high': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
        'medium': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
        'low': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N',
        'info': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
    }
    
    # Get all findings
    findings_url = f"{api_url}/pentestprojects/{project_id}/findings/"
    response = requests.get(findings_url, headers=headers, timeout=30)
    
    if response.status_code != 200:
        print(f"❌ Failed to get findings: {response.status_code}")
        return
    
    findings = response.json()
    
    # Find findings that need CVSS updates
    findings_to_update = []
    for finding in findings:
        cvss = finding['data'].get('cvss', '')
        title = finding['data'].get('title', '')
        
        # Check if CVSS needs updating (old format)
        if cvss and not cvss.startswith('CVSS:3.1/'):
            # Determine severity based on title and current CVSS
            if 'Multiple Conditional Access' in title or 'Azure security defaults' in title:
                severity = 'low'  # These are low severity from the Excel data
            elif 'Teams that contain' in title:
                severity = 'info'  # This is info severity from the Excel data
            else:
                continue  # Skip test findings and properly formatted ones
            
            findings_to_update.append({
                'id': finding['id'],
                'title': title,
                'current_cvss': cvss,
                'new_cvss': cvss_mapping[severity],
                'severity': severity,
                'data': finding['data']
            })
    
    print(f"Found {len(findings_to_update)} findings to update:")
    
    for finding in findings_to_update:
        print(f"\n  📝 {finding['title']}")
        print(f"     Current: {finding['current_cvss']}")
        print(f"     New:     {finding['new_cvss']}")
        
        # Update the finding
        finding_data = finding['data'].copy()
        finding_data['cvss'] = finding['new_cvss']
        
        update_payload = {
            'status': 'in-progress',
            'data': finding_data
        }
        
        update_url = f"{api_url}/pentestprojects/{project_id}/findings/{finding['id']}/"
        
        try:
            update_response = requests.patch(update_url, headers=headers, json=update_payload, timeout=30)
            
            if update_response.status_code in [200, 201]:
                print(f"     ✅ Updated successfully")
            else:
                print(f"     ❌ Update failed: {update_response.status_code}")
                print(f"        Error: {update_response.text[:100]}")
                
        except Exception as e:
            print(f"     ❌ Exception: {e}")
    
    print(f"\n🎯 CVSS vector update completed!")

if __name__ == "__main__":
    update_existing_cvss_vectors()