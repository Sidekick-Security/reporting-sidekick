#!/usr/bin/env python3

import os
import requests
import json
from ..parsers.m365_parser import M365Parser

class M365UploadProcessor:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.m365_parser = M365Parser(verbose=verbose)
        
        # Load API configuration
        try:
            import sys
            sys.path.append(os.path.join(os.path.dirname(__file__), '../../conf'))
            import conf
            self.api_url = conf.sysreptorAPIUrl
            self.api_headers = {'Authorization': conf.sysreptorAPI.replace('Authorization: ', '')}
        except ImportError:
            raise Exception("Could not load SysReptor API configuration from conf/conf.py")
    
    def upload_vulnerabilities_to_project(self, xlsx_file_path, project_id, upload_mode='grouped', filters=None):
        """
        Upload M365 vulnerabilities from Excel to SysReptor project
        
        Args:
            xlsx_file_path (str): Path to M365 Excel vulnerability report
            project_id (str): SysReptor project ID
            upload_mode (str): 'grouped' (group by Insight Label) or 'individual' (one per instance)
            filters (dict): Optional filters to apply to vulnerabilities
        """
        
        if self.verbose:
            print(f"Starting M365 vulnerability upload to project {project_id}")
            print(f"Excel file: {xlsx_file_path}")
            print(f"Upload mode: {upload_mode}")
            if filters:
                print(f"Filters: {filters}")
        
        # Validate inputs
        if not os.path.exists(xlsx_file_path):
            raise Exception(f"Excel file '{xlsx_file_path}' does not exist")
        
        # Validate project exists
        self._validate_project(project_id)
        
        # Parse M365 Excel file
        vulnerabilities = self.m365_parser.parse_m365_excel(xlsx_file_path)
        
        if not vulnerabilities:
            print("No M365 vulnerabilities found in Excel file")
            return
        
        if self.verbose:
            print(f"Found {len(vulnerabilities)} M365 vulnerabilities in Excel")
        
        # Apply filters if provided
        if filters:
            vulnerabilities = self.m365_parser.filter_vulnerabilities(vulnerabilities, filters)
        
        # Process vulnerabilities based on upload mode
        if upload_mode == 'grouped':
            processed_vulns = self.m365_parser.group_vulnerabilities_by_insight_label(vulnerabilities)
        else:  # individual
            processed_vulns = self._prepare_individual_vulnerabilities(vulnerabilities)
        
        if self.verbose:
            print(f"Prepared {len(processed_vulns)} vulnerability entries for upload")
        
        # Upload vulnerabilities
        upload_results = self._upload_to_sysreptor(processed_vulns, project_id)
        
        # Print results
        self._print_upload_results(upload_results)
        
        return upload_results
    
    def get_upload_preview(self, xlsx_file_path, upload_mode='grouped', filters=None):
        """
        Get preview of what would be uploaded without actually uploading
        
        Args:
            xlsx_file_path (str): Path to M365 Excel vulnerability report
            upload_mode (str): 'grouped' or 'individual'
            filters (dict): Optional filters to apply
            
        Returns:
            dict: Preview information
        """
        
        try:
            # Validate file exists
            if not os.path.exists(xlsx_file_path):
                return {'error': f"Excel file '{xlsx_file_path}' does not exist"}
            
            # Parse M365 Excel file
            vulnerabilities = self.m365_parser.parse_m365_excel(xlsx_file_path)
            
            if not vulnerabilities:
                return {'error': "No M365 vulnerabilities found in Excel file"}
            
            # Apply filters if provided
            if filters:
                vulnerabilities = self.m365_parser.filter_vulnerabilities(vulnerabilities, filters)
            
            # Process vulnerabilities based on upload mode
            if upload_mode == 'grouped':
                processed_vulns = self.m365_parser.group_vulnerabilities_by_insight_label(vulnerabilities)
            else:  # individual
                processed_vulns = self._prepare_individual_vulnerabilities(vulnerabilities)
            
            # Calculate severity distribution
            severity_distribution = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
            
            # Calculate category distribution
            category_distribution = {}
            for vuln in vulnerabilities:
                category = vuln.get('category', 'Unknown')
                category_distribution[category] = category_distribution.get(category, 0) + 1
            
            # Get sample vulnerabilities (up to 5)
            sample_vulnerabilities = []
            for vuln in processed_vulns[:5]:
                sample_vulnerabilities.append({
                    'upload_title': vuln.get('title', 'Unknown'),
                    'severity': vuln.get('severity', 'Unknown'),
                    'category': vuln.get('category', 'Unknown'),
                    'instance_count': vuln.get('instance_count', 1),
                    'validation': vuln.get('validation', 'Unknown')
                })
            
            return {
                'upload_mode': upload_mode,
                'total_vulnerabilities_in_excel': len(vulnerabilities),
                'vulnerabilities_to_upload': len(processed_vulns),
                'severity_distribution': severity_distribution,
                'category_distribution': category_distribution,
                'sample_vulnerabilities': sample_vulnerabilities,
                'filters_applied': filters or {}
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _validate_project(self, project_id):
        """Validate that the project exists and is accessible"""
        try:
            url = f"{self.api_url}/pentestprojects/{project_id}/"
            response = requests.get(url, headers=self.api_headers, timeout=30)
            
            if response.status_code == 404:
                raise Exception(f"Project '{project_id}' not found")
            elif response.status_code != 200:
                raise Exception(f"Failed to access project: {response.status_code}")
                
            project_data = response.json()
            if self.verbose:
                print(f"Project validated: {project_data.get('name', 'Unknown')}")
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to validate project: {str(e)}")
    
    def _group_vulnerabilities_by_title(self, vulnerabilities):
        """Group vulnerabilities by title and combine affected hosts"""
        grouped = {}
        
        for vuln in vulnerabilities:
            title = vuln.get('title', 'Unknown Vulnerability')
            
            if title not in grouped:
                grouped[title] = {
                    'title': title,
                    'description': vuln.get('description', ''),
                    'risk': vuln.get('risk', 'Medium'),
                    'cvss': vuln.get('cvss', '0.0'),
                    'affected_hosts': [],
                    'plugin_id': vuln.get('plugin_id', ''),
                    'solution': vuln.get('solution', ''),
                    'references': vuln.get('references', ''),
                    'count': 0
                }
            
            # Add host information
            host = vuln.get('host', 'Unknown')
            if host not in grouped[title]['affected_hosts']:
                grouped[title]['affected_hosts'].append(host)
            
            grouped[title]['count'] += 1
        
        # Convert to list and add affected hosts string
        result = []
        for title, vuln_data in grouped.items():
            vuln_data['affected_hosts_string'] = ', '.join(vuln_data['affected_hosts'])
            result.append(vuln_data)
        
        return result
    
    def _prepare_individual_vulnerabilities(self, vulnerabilities):
        """Prepare vulnerabilities as individual entries"""
        result = []
        
        for vuln in vulnerabilities:
            result.append({
                'title': f"{vuln.get('title', 'Unknown')} - {vuln.get('host', 'Unknown Host')}",
                'description': vuln.get('description', ''),
                'risk': vuln.get('risk', 'Medium'),
                'cvss': vuln.get('cvss', '0.0'),
                'affected_hosts_string': vuln.get('host', 'Unknown'),
                'plugin_id': vuln.get('plugin_id', ''),
                'solution': vuln.get('solution', ''),
                'references': vuln.get('references', ''),
                'count': 1
            })
        
        return result
    
    def _upload_to_sysreptor(self, vulnerabilities, project_id):
        """Upload M365 vulnerabilities to SysReptor project"""
        results = {
            'successful': 0,
            'failed': 0,
            'errors': []
        }
        
        for vuln in vulnerabilities:
            try:
                # Format affected components as list
                affected_components_list = []
                instance_count = vuln.get('instance_count', 1)
                
                # If more than 10 instances, use generic message
                if instance_count > 10:
                    affected_components_list = ["View all instances of this finding in the Excel spreadsheet"]
                else:
                    # Show actual components for 10 or fewer instances
                    if 'instances' in vuln and vuln['instances']:
                        for instance in vuln['instances']:
                            component = instance.get('affected_component', '').strip().replace('\n', ' ').replace('\r', '')
                            if component and component not in affected_components_list:
                                affected_components_list.append(component)
                    elif vuln.get('affected_components'):
                        # Split by newlines and clean up
                        components = vuln['affected_components'].split('\n\n')
                        for comp in components:
                            comp = comp.strip().replace('\n', ' ').replace('\r', '')
                            if comp and comp not in affected_components_list:
                                affected_components_list.append(comp)
                
                # Create finding data structure for SysReptor M365 project
                finding_data = {
                    'status': 'in-progress',  # Valid status choice
                    'data': {
                        'title': vuln.get('title', 'Unknown M365 Finding'),
                        'cvss': self._map_severity_to_cvss(vuln.get('severity', 'medium')),
                        'High_Level_Description': vuln.get('description', ''),
                        'Technical_Details': '',  # Left blank as requested
                        'affected_components': affected_components_list,
                        'recommendation': vuln.get('solution', ''),
                        'retest_status': 'new',
                        'compliance_implications': ''  # Left blank as requested
                    }
                }
                
                # Upload to SysReptor
                url = f"{self.api_url}/pentestprojects/{project_id}/findings/"
                response = requests.post(
                    url, 
                    headers={**self.api_headers, 'Content-Type': 'application/json'},
                    json=finding_data,
                    timeout=30
                )
                
                if response.status_code in [200, 201]:
                    results['successful'] += 1
                    if self.verbose:
                        instance_info = f" ({vuln.get('instance_count', 1)} instances)" if vuln.get('instance_count', 1) > 1 else ""
                        print(f"✓ Uploaded: {vuln['title']}{instance_info}")
                else:
                    results['failed'] += 1
                    error_msg = f"Failed to upload '{vuln['title']}': {response.status_code}"
                    if self.verbose:
                        try:
                            error_details = response.json()
                            error_msg += f" - {error_details}"
                        except:
                            error_msg += f" - {response.text[:200]}"
                    results['errors'].append(error_msg)
                    if self.verbose:
                        print(f"✗ {error_msg}")
                        
            except Exception as e:
                results['failed'] += 1
                error_msg = f"Exception uploading '{vuln.get('title', 'Unknown')}': {str(e)}"
                results['errors'].append(error_msg)
                if self.verbose:
                    print(f"✗ {error_msg}")
        
        return results
    
    def _format_instances_for_upload(self, instances):
        """Format instances list for SysReptor upload"""
        formatted_instances = []
        
        for instance in instances[:50]:  # Limit to first 50 instances
            parts = []
            if instance.get('affected_component'):
                parts.append(f"Component: {instance['affected_component']}")
            if instance.get('meta_label'):
                parts.append(f"Label: {instance['meta_label']}")
            if instance.get('object_type'):
                parts.append(f"Type: {instance['object_type']}")
            if instance.get('first_seen'):
                parts.append(f"First Seen: {instance['first_seen']}")
            
            if parts:
                formatted_instances.append(" | ".join(parts))
        
        result = "\n".join(formatted_instances)
        
        if len(instances) > 50:
            result += f"\n\n... and {len(instances) - 50} more instances"
        
        return result
    
    def _map_risk_to_severity(self, risk):
        """Map risk level to SysReptor severity"""
        risk_mapping = {
            'Critical': 'critical',
            'High': 'high', 
            'Medium': 'medium',
            'Low': 'low',
            'Info': 'info',
            'Informational': 'info'
        }
        return risk_mapping.get(risk, 'medium')
    
    def _map_severity_to_cvss(self, severity):
        """Map severity to CVSS 3.1 vector string for M365 findings"""
        severity_to_cvss = {
            'critical': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',  # 9.0+ Critical
            'high': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',       # 7.0-8.9 High  
            'medium': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',     # 4.0-6.9 Medium
            'low': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N',        # 0.1-3.9 Low
            'info': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'        # 0.0 Informational
        }
        return severity_to_cvss.get(severity.lower(), 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N')
    
    def _print_upload_results(self, results):
        """Print formatted upload results"""
        print(f"\n=== M365 Upload Results ===")
        print(f"✓ Successful uploads: {results['successful']}")
        print(f"✗ Failed uploads: {results['failed']}")
        
        if results['errors']:
            print(f"\nErrors encountered:")
            for error in results['errors'][:10]:  # Show first 10 errors
                print(f"  - {error}")
            
            if len(results['errors']) > 10:
                print(f"  ... and {len(results['errors']) - 10} more errors")
        
        if results['successful'] > 0:
            print(f"\n🎉 Successfully uploaded {results['successful']} M365 vulnerabilities!")