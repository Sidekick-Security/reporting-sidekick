#!/usr/bin/env python3

import os
import requests
import json
from ..parsers.xlsx_parser import XLSXParser

class VulnUploadProcessor:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.xlsx_parser = XLSXParser(verbose=verbose)
        
        # Load API configuration
        try:
            import sys
            sys.path.append(os.path.join(os.path.dirname(__file__), '../../conf'))
            import conf
            self.api_url = conf.sysreptorAPIUrl
            self.api_headers = {'Authorization': conf.sysreptorAPI.replace('Authorization: ', '')}
        except ImportError:
            raise Exception("Could not load SysReptor API configuration from conf/conf.py")
    
    def upload_vulnerabilities_to_project(self, xlsx_file_path, project_id, upload_mode='grouped'):
        """
        Upload vulnerabilities from XLSX to SysReptor project
        
        Args:
            xlsx_file_path (str): Path to XLSX vulnerability report
            project_id (str): SysReptor project ID
            upload_mode (str): 'grouped' (group by title) or 'individual' (one per instance)
        """
        
        if self.verbose:
            print(f"Starting vulnerability upload to project {project_id}")
            print(f"XLSX file: {xlsx_file_path}")
            print(f"Upload mode: {upload_mode}")
        
        # Validate inputs
        if not os.path.exists(xlsx_file_path):
            raise Exception(f"XLSX file '{xlsx_file_path}' does not exist")
        
        # Validate project exists
        self._validate_project(project_id)
        
        # Parse XLSX file
        vulnerabilities = self.xlsx_parser.parse_xlsx_report(xlsx_file_path)
        
        if not vulnerabilities:
            print("No vulnerabilities found in XLSX file")
            return
        
        if self.verbose:
            print(f"Parsed {len(vulnerabilities)} vulnerabilities from XLSX")
        
        # Group vulnerabilities if needed
        if upload_mode == 'grouped':
            grouped_vulns = self.xlsx_parser.group_vulnerabilities_by_title(vulnerabilities)
            if self.verbose:
                print(f"Grouped into {len(grouped_vulns)} unique vulnerability types")
            vulnerabilities_to_upload = self._prepare_grouped_vulnerabilities(grouped_vulns)
        else:
            vulnerabilities_to_upload = self._prepare_individual_vulnerabilities(vulnerabilities)
        
        # Show preview and get user confirmation
        selected_vulns = self._prompt_for_upload_selection(vulnerabilities_to_upload)
        
        if not selected_vulns:
            print("No vulnerabilities selected for upload")
            return
        
        # Upload selected vulnerabilities
        self._upload_vulnerabilities(project_id, selected_vulns)
    
    def _validate_project(self, project_id):
        """Validate that the project exists and is accessible"""
        try:
            url = f"{self.api_url}pentestprojects/{project_id}"
            response = requests.get(url, headers=self.api_headers)
            
            if response.status_code != 200:
                raise Exception(f"Project {project_id} not found or not accessible")
            
            project_data = response.json()
            if self.verbose:
                print(f"✓ Project validated: {project_data.get('name', 'Unknown')}")
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error accessing SysReptor API: {str(e)}")
    
    def _prepare_grouped_vulnerabilities(self, grouped_vulns):
        """Prepare grouped vulnerabilities for upload"""
        prepared = []
        
        for title, group_data in grouped_vulns.items():
            vuln = group_data['vulnerability']
            affected_components = group_data['affected_components']
            
            # Build SysReptor finding data
            finding_data = {
                'title': vuln['title'],
                'risk_description': vuln['description'] or f"Vulnerability: {vuln['title']}",
                'recommendation': vuln['solution'] or "Review and remediate this vulnerability according to security best practices",
                'affected_components': affected_components,
                'cvss_number': vuln['cvss_score'],
                'risk_rating': vuln['risk'],
                'retest_status': 'open'
            }
            
            # Add optional fields if available
            if vuln['cve_references']:
                finding_data['cve_references'] = vuln['cve_references']
            
            if vuln['vulnerability_type']:
                finding_data['vulnerability_type'] = vuln['vulnerability_type']
            
            prepared.append({
                'upload_title': title,
                'affected_count': len(affected_components),
                'risk': vuln['risk'],
                'cvss': vuln['cvss_score'],
                'finding_data': finding_data
            })
        
        return prepared
    
    def _prepare_individual_vulnerabilities(self, vulnerabilities):
        """Prepare individual vulnerabilities for upload"""
        prepared = []
        
        for vuln in vulnerabilities:
            # Build affected component
            component = self.xlsx_parser._build_component_string(vuln)
            affected_components = [component] if component else []
            
            # Build SysReptor finding data
            finding_data = {
                'title': vuln['title'],
                'risk_description': vuln['description'] or f"Vulnerability: {vuln['title']}",
                'recommendation': vuln['solution'] or "Review and remediate this vulnerability according to security best practices",
                'affected_components': affected_components,
                'cvss_number': vuln['cvss_score'],
                'risk_rating': vuln['risk'],
                'retest_status': 'open'
            }
            
            # Add optional fields if available
            if vuln['cve_references']:
                finding_data['cve_references'] = vuln['cve_references']
            
            if vuln['vulnerability_type']:
                finding_data['vulnerability_type'] = vuln['vulnerability_type']
            
            upload_title = f"{vuln['title']}"
            if component:
                upload_title += f" ({component})"
            
            prepared.append({
                'upload_title': upload_title,
                'affected_count': len(affected_components),
                'risk': vuln['risk'],
                'cvss': vuln['cvss_score'],
                'finding_data': finding_data
            })
        
        return prepared
    
    def _prompt_for_upload_selection(self, vulnerabilities_to_upload):
        """Prompt user to select vulnerabilities for upload"""
        print(f"\n=== Vulnerabilities Available for Upload ===")
        print(f"Found {len(vulnerabilities_to_upload)} vulnerabilities ready for upload:")
        print()
        
        # Sort by risk and CVSS score
        risk_priority = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        sorted_vulns = sorted(
            vulnerabilities_to_upload,
            key=lambda x: (risk_priority.get(x['risk'], 0), x['cvss']),
            reverse=True
        )
        
        # Display numbered list
        for i, vuln in enumerate(sorted_vulns, 1):
            title = vuln['upload_title']
            risk = vuln['risk']
            cvss = vuln['cvss']
            affected_count = vuln['affected_count']
            
            print(f"{i:2d}. {title} [{risk}] - CVSS: {cvss}")
            if affected_count > 1:
                print(f"    → Affects {affected_count} components")
        
        print()
        print("Enter the numbers of vulnerabilities to upload (e.g., 1,3,5-7,10):")
        print("Press Enter to upload all vulnerabilities, or 'q' to cancel")
        
        try:
            user_input = input("Selection: ").strip()
            
            if user_input.lower() == 'q':
                return []
            
            if not user_input:
                return sorted_vulns
            
            # Parse selection
            selected_indices = self._parse_selection(user_input, len(sorted_vulns))
            selected_vulns = [sorted_vulns[i-1] for i in selected_indices]
            
            print(f"\nSelected {len(selected_vulns)} vulnerabilities for upload.")
            return selected_vulns
                
        except KeyboardInterrupt:
            print("\nUpload cancelled by user.")
            return []
        except Exception as e:
            print(f"Error during selection: {str(e)}")
            return []
    
    def _parse_selection(self, selection_str, max_count):
        """Parse user selection string (e.g., '1,3,5-7,10') into list of indices"""
        selected = set()
        
        try:
            parts = selection_str.split(',')
            for part in parts:
                part = part.strip()
                if '-' in part:
                    # Handle range (e.g., '5-7')
                    start, end = part.split('-', 1)
                    start = int(start.strip())
                    end = int(end.strip())
                    
                    if start < 1 or end > max_count or start > end:
                        raise ValueError(f"Invalid range: {part}")
                    
                    for i in range(start, end + 1):
                        selected.add(i)
                else:
                    # Handle single number
                    num = int(part)
                    if num < 1 or num > max_count:
                        raise ValueError(f"Invalid number: {num}")
                    selected.add(num)
            
            return sorted(list(selected))
            
        except ValueError as e:
            raise Exception(f"Invalid selection format: {str(e)}")
    
    def _upload_vulnerabilities(self, project_id, vulnerabilities):
        """Upload vulnerabilities to SysReptor project"""
        successful_uploads = 0
        failed_uploads = 0
        
        print(f"\nUploading {len(vulnerabilities)} vulnerabilities to SysReptor...")
        print("=" * 60)
        
        for vuln in vulnerabilities:
            try:
                # Create finding payload
                payload = {
                    'data': vuln['finding_data']
                }
                
                # POST to SysReptor API
                url = f"{self.api_url}pentestprojects/{project_id}/findings"
                response = requests.post(url, headers=self.api_headers, json=payload)
                response.raise_for_status()
                
                finding_data = response.json()
                successful_uploads += 1
                
                if self.verbose:
                    print(f"✓ Uploaded: {vuln['upload_title']} (ID: {finding_data.get('id')})")
                else:
                    print(f"✓ {vuln['upload_title']}")
                
            except Exception as e:
                failed_uploads += 1
                print(f"✗ Failed: {vuln['upload_title']} - {str(e)}")
        
        # Summary
        print("=" * 60)
        print(f"Upload Summary:")
        print(f"✓ Successfully uploaded: {successful_uploads}")
        if failed_uploads > 0:
            print(f"✗ Failed uploads: {failed_uploads}")
        print(f"Total processed: {len(vulnerabilities)}")
        
        if successful_uploads > 0:
            print(f"\n🎉 Successfully uploaded {successful_uploads} vulnerabilities to SysReptor project!")
    
    def get_upload_preview(self, xlsx_file_path, upload_mode='grouped'):
        """Get preview of what would be uploaded without actually uploading"""
        try:
            vulnerabilities = self.xlsx_parser.parse_xlsx_report(xlsx_file_path)
            
            if upload_mode == 'grouped':
                grouped_vulns = self.xlsx_parser.group_vulnerabilities_by_title(vulnerabilities)
                prepared = self._prepare_grouped_vulnerabilities(grouped_vulns)
            else:
                prepared = self._prepare_individual_vulnerabilities(vulnerabilities)
            
            # Generate preview statistics
            preview = {
                'total_vulnerabilities_in_xlsx': len(vulnerabilities),
                'vulnerabilities_to_upload': len(prepared),
                'upload_mode': upload_mode,
                'risk_distribution': {},
                'sample_vulnerabilities': prepared[:5]  # Show first 5
            }
            
            # Risk distribution
            for vuln in prepared:
                risk = vuln['risk']
                preview['risk_distribution'][risk] = preview['risk_distribution'].get(risk, 0) + 1
            
            return preview
            
        except Exception as e:
            return {'error': str(e)}