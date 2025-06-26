#!/usr/bin/env python3

import requests
import json
import sys
import os

def test_api_endpoints():
    """Test various SysReptor API endpoints to find the correct one"""
    
    print("=== Debugging SysReptor API Connectivity ===")
    
    # Load configuration
    sys.path.append(os.path.join(os.path.dirname(__file__), 'conf'))
    import conf
    
    base_url = "https://sidekick.sysre.pt"
    api_token = conf.sysreptorAPI.replace('Authorization: ', '')
    
    print(f"Base URL: {base_url}")
    print(f"Token: {api_token[:20]}...")
    
    headers = {
        'Authorization': api_token,
        'Content-Type': 'application/json'
    }
    
    # Test different API endpoints
    endpoints_to_test = [
        "/api/v1/projects/",
        "/api/projects/", 
        "/projects/",
        "/api/v1/",
        "/api/",
        "/api/v1/pendingtests/",
        "/api/v1/projecttypes/",
        "/api/v1/findingtemplates/"
    ]
    
    working_endpoints = []
    
    for endpoint in endpoints_to_test:
        url = base_url + endpoint
        print(f"\nTesting: {url}")
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            print(f"  Status: {response.status_code}")
            
            if response.status_code == 200:
                print(f"  ✅ SUCCESS!")
                try:
                    data = response.json()
                    if isinstance(data, dict):
                        print(f"  Keys: {list(data.keys())}")
                    elif isinstance(data, list):
                        print(f"  List length: {len(data)}")
                        if data and isinstance(data[0], dict):
                            print(f"  Sample keys: {list(data[0].keys())}")
                    working_endpoints.append((endpoint, response.status_code))
                except:
                    print(f"  Response: {response.text[:100]}...")
            elif response.status_code == 401:
                print(f"  ❌ Unauthorized - check token")
            elif response.status_code == 403:
                print(f"  ❌ Forbidden - check permissions")
            elif response.status_code == 404:
                print(f"  ❌ Not Found")
            else:
                print(f"  ❌ Error: {response.status_code}")
                print(f"  Response: {response.text[:100]}...")
                
        except requests.exceptions.Timeout:
            print(f"  ❌ Timeout")
        except requests.exceptions.ConnectionError:
            print(f"  ❌ Connection Error")
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    print(f"\n=== Working Endpoints ===")
    for endpoint, status in working_endpoints:
        print(f"✅ {endpoint} - {status}")
    
    return working_endpoints

def test_project_access():
    """Test accessing the specific project"""
    print(f"\n=== Testing Project Access ===")
    
    sys.path.append(os.path.join(os.path.dirname(__file__), 'conf'))
    import conf
    
    base_url = "https://sidekick.sysre.pt"
    api_token = conf.sysreptorAPI.replace('Authorization: ', '')
    project_id = "0e2f7b0f-b1aa-4957-9b3c-43fc5dee9bf3"
    
    headers = {
        'Authorization': api_token,
        'Content-Type': 'application/json'
    }
    
    # Try different project endpoints
    project_endpoints = [
        f"/api/v1/projects/{project_id}/",
        f"/api/projects/{project_id}/",
        f"/projects/{project_id}/",
        f"/api/v1/projects/{project_id}/findings/",
        f"/api/projects/{project_id}/findings/"
    ]
    
    for endpoint in project_endpoints:
        url = base_url + endpoint
        print(f"\nTesting project endpoint: {url}")
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            print(f"  Status: {response.status_code}")
            
            if response.status_code == 200:
                print(f"  ✅ Project accessible!")
                try:
                    data = response.json()
                    if 'name' in data:
                        print(f"  Project name: {data['name']}")
                    if 'status' in data:
                        print(f"  Project status: {data['status']}")
                    return endpoint
                except:
                    print(f"  Response: {response.text[:200]}...")
            else:
                print(f"  ❌ {response.status_code}: {response.text[:100]}...")
                
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    return None

def test_findings_upload():
    """Test uploading a sample finding"""
    print(f"\n=== Testing Sample Finding Upload ===")
    
    sys.path.append(os.path.join(os.path.dirname(__file__), 'conf'))
    import conf
    
    base_url = "https://sidekick.sysre.pt"
    api_token = conf.sysreptorAPI.replace('Authorization: ', '')
    project_id = "0e2f7b0f-b1aa-4957-9b3c-43fc5dee9bf3"
    
    headers = {
        'Authorization': api_token,
        'Content-Type': 'application/json'
    }
    
    # Sample finding data
    test_finding = {
        "title": "M365 Test Finding - API Connectivity Check",
        "description": "This is a test finding to verify M365Review upload functionality",
        "severity": "low",
        "status": "new",
        "affected_components": "Test Component",
        "solution": "This is a test - no action needed",
        "source": "M365 Review Test"
    }
    
    # Try different finding upload endpoints
    upload_endpoints = [
        f"/api/v1/projects/{project_id}/findings/",
        f"/api/projects/{project_id}/findings/",
        f"/projects/{project_id}/findings/"
    ]
    
    for endpoint in upload_endpoints:
        url = base_url + endpoint
        print(f"\nTesting upload to: {url}")
        
        try:
            response = requests.post(url, headers=headers, json=test_finding, timeout=15)
            print(f"  Status: {response.status_code}")
            
            if response.status_code in [200, 201]:
                print(f"  ✅ Finding uploaded successfully!")
                try:
                    data = response.json()
                    if 'id' in data:
                        print(f"  Finding ID: {data['id']}")
                    return data
                except:
                    print(f"  Response: {response.text[:200]}...")
                    return True
            else:
                print(f"  ❌ {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"  Error details: {error_data}")
                except:
                    print(f"  Error text: {response.text[:200]}...")
                    
        except Exception as e:
            print(f"  ❌ Exception: {e}")
    
    return None

def main():
    print("SysReptor API Debug Tool")
    print("=" * 50)
    
    # Test basic connectivity
    working_endpoints = test_api_endpoints()
    
    if working_endpoints:
        # Test project access
        project_endpoint = test_project_access()
        
        if project_endpoint:
            # Test finding upload
            upload_result = test_findings_upload()
            
            if upload_result:
                print(f"\n🎉 SUCCESS: API is working and finding uploaded!")
            else:
                print(f"\n❌ Upload failed but project is accessible")
        else:
            print(f"\n❌ Project not accessible")
    else:
        print(f"\n❌ No working API endpoints found")
    
    print(f"\n=== Recommendations ===")
    if working_endpoints:
        print(f"1. Update API URL in conf.py to use working endpoint")
        print(f"2. Test M365Review upload again")
    else:
        print(f"1. Check API token validity")
        print(f"2. Verify SysReptor instance is accessible")
        print(f"3. Check if API endpoints have changed")

if __name__ == "__main__":
    main()