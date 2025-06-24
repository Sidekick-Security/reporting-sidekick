#!/usr/bin/env python3

import os
import requests
import json
from typing import List, Dict, Optional
from ..integrations.chatgpt_client import ChatGPTClient

class ReportCompletionProcessor:
    def __init__(self, verbose=False):
        self.verbose = verbose
        
        # Load API configurations
        try:
            import sys
            sys.path.append(os.path.join(os.path.dirname(__file__), '../../conf'))
            import conf
            self.api_url = conf.sysreptorAPIUrl
            self.api_headers = {'Authorization': conf.sysreptorAPI.replace('Authorization: ', '')}
            
            # Initialize ChatGPT client
            self.chatgpt_client = ChatGPTClient(conf.chatgptAPIKey, verbose=verbose)
            
        except ImportError:
            raise Exception("Could not load API configurations from conf/conf.py")
    
    def complete_report_sections(self, project_id: str, sections: List[str] = None):
        """
        Complete specified report sections using ChatGPT
        
        Args:
            project_id (str): SysReptor project ID
            sections (List[str]): List of sections to complete. Options: 
                                ['executive_summary', 'identified_risks', 'compliance_impact']
                                If None, completes all available sections
        """
        
        if self.verbose:
            print(f"Starting report completion for project {project_id}")
        
        # Validate project exists
        self._validate_project(project_id)
        
        # Get project findings for context
        findings_data = self._get_project_findings(project_id)
        project_context = self._get_project_context(project_id)
        
        if self.verbose:
            print(f"Found {len(findings_data)} findings to analyze")
        
        # Test ChatGPT connection
        if not self.chatgpt_client.test_connection():
            raise Exception("Failed to connect to ChatGPT API")
        
        if self.verbose:
            print("✓ ChatGPT connection verified")
        
        # Determine sections to complete
        if sections is None:
            sections = ['executive_summary', 'identified_risks', 'compliance_impact']
        
        # Complete each section
        completed_sections = []
        failed_sections = []
        
        for section in sections:
            try:
                if self.verbose:
                    print(f"\n=== Completing {section.replace('_', ' ').title()} ===")
                
                success = self._complete_section(project_id, section, findings_data, project_context)
                
                if success:
                    completed_sections.append(section)
                    if self.verbose:
                        print(f"✓ Completed {section}")
                else:
                    failed_sections.append(section)
                    print(f"✗ Failed to complete {section}")
                    
            except Exception as e:
                failed_sections.append(section)
                print(f"✗ Error completing {section}: {str(e)}")
        
        # Summary
        print(f"\n=== Report Completion Summary ===")
        print(f"✓ Successfully completed: {len(completed_sections)} sections")
        if completed_sections:
            print(f"  - {', '.join([s.replace('_', ' ').title() for s in completed_sections])}")
        
        if failed_sections:
            print(f"✗ Failed to complete: {len(failed_sections)} sections")
            print(f"  - {', '.join([s.replace('_', ' ').title() for s in failed_sections])}")
        
        return completed_sections, failed_sections
    
    def _validate_project(self, project_id: str):
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
    
    def _get_project_findings(self, project_id: str) -> List[Dict]:
        """Get all findings from the project"""
        try:
            url = f"{self.api_url}pentestprojects/{project_id}/findings"
            response = requests.get(url, headers=self.api_headers)
            response.raise_for_status()
            
            findings = response.json()
            
            # Extract relevant data from findings
            processed_findings = []
            for finding in findings:
                data = finding.get('data', {})
                processed_findings.append({
                    'id': finding.get('id'),
                    'title': data.get('title', 'Unknown'),
                    'risk': data.get('risk_rating', 'Unknown'),
                    'description': data.get('risk_description', ''),
                    'recommendation': data.get('recommendation', ''),
                    'affected_components': data.get('affected_components', []),
                    'cvss_number': data.get('cvss_number', 0),
                    'cve_references': data.get('cve_references', ''),
                    'vulnerability_type': self._categorize_finding(data.get('title', ''))
                })
            
            return processed_findings
            
        except Exception as e:
            if self.verbose:
                print(f"Warning: Could not fetch findings: {str(e)}")
            return []
    
    def _get_project_context(self, project_id: str) -> Dict:
        """Get project context information"""
        try:
            # Get project details
            url = f"{self.api_url}pentestprojects/{project_id}"
            response = requests.get(url, headers=self.api_headers)
            project_data = response.json()
            
            # Get sections for additional context
            sections_url = f"{self.api_url}pentestprojects/{project_id}/sections"
            sections_response = requests.get(sections_url, headers=self.api_headers)
            sections_data = sections_response.json()
            
            context = {
                'project_name': project_data.get('name', 'Unknown Project'),
                'project_type': 'Vulnerability Scan',  # Default
                'scope': '',
                'timeframe': '',
                'compliance_frameworks': []
            }
            
            # Extract context from sections
            for section in sections_data:
                section_id = section.get('id', '')
                data = section.get('data', {})
                
                if section_id == 'scope':
                    context['scope'] = data.get('scope', '')
                    context['timeframe'] = f"{data.get('start_date', '')} to {data.get('end_date', '')}"
                
                elif section_id == 'Compliance_Impact_and_Analysis':
                    frameworks = []
                    for i in range(1, 4):
                        framework = data.get(f'Compliance_Framework{i}', '')
                        if framework and framework != 'N/A':
                            frameworks.append(framework)
                    context['compliance_frameworks'] = frameworks
            
            return context
            
        except Exception as e:
            if self.verbose:
                print(f"Warning: Could not fetch project context: {str(e)}")
            return {
                'project_name': 'Unknown Project',
                'project_type': 'Vulnerability Scan',
                'scope': '',
                'timeframe': '',
                'compliance_frameworks': []
            }
    
    def _complete_section(self, project_id: str, section_type: str, findings_data: List[Dict], project_context: Dict) -> bool:
        """Complete a specific section"""
        try:
            if section_type == 'executive_summary':
                return self._complete_executive_summary(project_id, findings_data, project_context)
            elif section_type == 'identified_risks':
                return self._complete_identified_risks(project_id, findings_data, project_context)
            elif section_type == 'compliance_impact':
                return self._complete_compliance_impact(project_id, findings_data, project_context)
            else:
                print(f"Unknown section type: {section_type}")
                return False
                
        except Exception as e:
            if self.verbose:
                print(f"Error completing {section_type}: {str(e)}")
            return False
    
    def _complete_executive_summary(self, project_id: str, findings_data: List[Dict], project_context: Dict) -> bool:
        """Complete the executive summary section"""
        
        # Generate content using ChatGPT with correct parameters
        content = self.chatgpt_client.generate_executive_summary(project_context, findings_data)
        
        # Update SysReptor section
        return self._update_section_field(project_id, 'executive_summary', 'executive_summary', content)
    
    def _complete_identified_risks(self, project_id: str, findings_data: List[Dict], project_context: Dict) -> bool:
        """Complete the identified risks section"""
        
        # Generate business risks summary
        business_risks_content = self.chatgpt_client.generate_identified_risks(
            findings_data, project_context
        )
        
        # Generate high-level recommendations using new template-based method
        recommendations_content = self.chatgpt_client.generate_high_level_recommendations(
            project_context, findings_data
        )
        
        # Update both fields
        success1 = self._update_section_field(project_id, 'Identified_Risks', 'Summary_of_Business_Risks', business_risks_content)
        success2 = self._update_section_field(project_id, 'Identified_Risks', 'High_Level_Recommendations', recommendations_content)
        
        return success1 and success2
    
    def _complete_compliance_impact(self, project_id: str, findings_data: List[Dict], project_context: Dict) -> bool:
        """Complete the compliance impact section and update individual finding compliance implications"""
        
        frameworks = project_context.get('compliance_frameworks', ['SOC 2', 'NIST CSF'])
        
        # Generate compliance mappings for the specific field
        compliance_mappings = self.chatgpt_client.get_compliance_mappings(findings_data, frameworks)
        
        # Update the compliance mappings field
        mappings_success = self._update_section_field(project_id, 'Compliance_Impact_and_Analysis', 'Compliance_Mappings', compliance_mappings)
        
        # Update individual finding compliance implications
        implications_success = self._update_finding_compliance_implications(project_id, findings_data, frameworks, compliance_mappings)
        
        return mappings_success and implications_success
    
    def _update_finding_compliance_implications(self, project_id: str, findings_data: List[Dict], frameworks: List[str], compliance_mappings: str) -> bool:
        """Update compliance implications for each individual finding"""
        try:
            if self.verbose:
                print(f"  Updating compliance implications for {len(findings_data)} findings")
            
            # Parse compliance mappings to get structured data
            try:
                mappings_data = json.loads(compliance_mappings)
            except json.JSONDecodeError:
                # If compliance_mappings is not JSON, create a basic structure
                mappings_data = {}
            
            successful_updates = 0
            failed_updates = 0
            
            for finding in findings_data:
                finding_id = finding.get('id')
                finding_title = finding.get('title', '')
                
                if not finding_id:
                    continue
                
                try:
                    # Generate compliance implications for this specific finding
                    implications = self.chatgpt_client.generate_finding_compliance_implications(
                        finding, frameworks, mappings_data
                    )
                    
                    # Format the implications using the same format as the reference code
                    formatted_implications = self._format_finding_implications(implications)
                    
                    # Update the finding's compliance implications field
                    success = self._update_finding_field(project_id, finding_id, 'compliance_implications', formatted_implications)
                    
                    if success:
                        successful_updates += 1
                        if self.verbose:
                            print(f"    ✓ Updated compliance implications for: {finding_title}")
                    else:
                        failed_updates += 1
                        if self.verbose:
                            print(f"    ✗ Failed to update compliance implications for: {finding_title}")
                
                except Exception as e:
                    failed_updates += 1
                    if self.verbose:
                        print(f"    ✗ Error updating {finding_title}: {str(e)}")
            
            if self.verbose:
                print(f"  Compliance implications update summary: {successful_updates} successful, {failed_updates} failed")
            
            return successful_updates > 0 and failed_updates == 0
            
        except Exception as e:
            if self.verbose:
                print(f"  ✗ Error updating finding compliance implications: {str(e)}")
            return False
    
    def _format_finding_implications(self, implications: Dict) -> str:
        """
        Format compliance implications into the expected text format.
        Handles nested framework structures and ensures all frameworks are processed.
        
        Args:
            implications (dict): Compliance implications for the finding with framework controls
            
        Returns:
            str: Formatted text for the compliance implications field
        """
        formatted_text = "The following controls are impacted based on this finding:\n\n"
        
        try:
            # Handle case where implications might be None or empty
            if not implications or "error" in implications:
                formatted_text += "No compliance implications identified.\n"
                return formatted_text

            # Process each framework's implications
            for framework_name, framework_data in implications.items():
                if not framework_data:  # Skip empty framework data
                    continue
                    
                framework_text = f"**{framework_name}**\n"
                has_controls = False
                
                # Process controls for this framework
                for control_id, control_data in framework_data.items():
                    # Skip if control_data is not in expected format
                    if not isinstance(control_data, dict):
                        continue
                        
                    title = control_data.get('title', 'No title available')
                    description = control_data.get('description', 'No description available')
                    
                    framework_text += f"* **{control_id} - {title}:** {description}\n"
                    has_controls = True
                
                # Only add framework section if it has controls
                if has_controls:
                    formatted_text += framework_text + "\n"
            
            # If no valid implications were found
            if formatted_text == "The following controls are impacted based on this finding:\n\n":
                formatted_text += "No specific compliance controls were identified for this finding.\n"
            
            return formatted_text
            
        except Exception as e:
            return f"Error processing compliance implications: {str(e)}\n"

    def _update_finding_field(self, project_id: str, finding_id: str, field_name: str, content: str) -> bool:
        """Update a specific field in a finding"""
        try:
            # Get current finding data
            url = f"{self.api_url}pentestprojects/{project_id}/findings/{finding_id}"
            response = requests.get(url, headers=self.api_headers)
            response.raise_for_status()
            
            finding_data = response.json()
            current_data = finding_data.get('data', {})
            
            # Update the specific field
            current_data[field_name] = content
            
            # Prepare update payload
            update_payload = {'data': current_data}
            
            # Update finding
            response = requests.patch(url, headers=self.api_headers, json=update_payload)
            response.raise_for_status()
            
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"      ✗ Failed to update finding {field_name}: {str(e)}")
            return False
    
    def _update_section_field(self, project_id: str, section_id: str, field_name: str, content: str) -> bool:
        """Update a specific field in a SysReptor section"""
        try:
            # Get current section data
            url = f"{self.api_url}pentestprojects/{project_id}/sections/{section_id}"
            response = requests.get(url, headers=self.api_headers)
            response.raise_for_status()
            
            section_data = response.json()
            current_data = section_data.get('data', {})
            
            # Update the specific field
            current_data[field_name] = content
            
            # Prepare update payload
            update_payload = {'data': current_data}
            
            # Update section
            response = requests.patch(url, headers=self.api_headers, json=update_payload)
            response.raise_for_status()
            
            if self.verbose:
                print(f"  ✓ Updated {field_name} ({len(content)} characters)")
            
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"  ✗ Failed to update {field_name}: {str(e)}")
            return False
    
    def _categorize_finding(self, title: str) -> str:
        """Categorize finding type based on title"""
        title_lower = title.lower()
        
        if any(keyword in title_lower for keyword in ['sql', 'injection', 'xss', 'csrf']):
            return 'Web Application Security'
        elif any(keyword in title_lower for keyword in ['network', 'port', 'service', 'protocol']):
            return 'Network Security'
        elif any(keyword in title_lower for keyword in ['auth', 'password', 'credential', 'access']):
            return 'Access Control'
        elif any(keyword in title_lower for keyword in ['config', 'setting', 'hardening']):
            return 'Configuration'
        elif any(keyword in title_lower for keyword in ['crypto', 'ssl', 'tls', 'certificate']):
            return 'Cryptography'
        else:
            return 'General Security'
    
    def preview_completion(self, project_id: str, sections: List[str] = None) -> Dict:
        """Preview what would be completed without actually doing it"""
        try:
            self._validate_project(project_id)
            findings_data = self._get_project_findings(project_id)
            project_context = self._get_project_context(project_id)
            
            if sections is None:
                sections = ['executive_summary', 'identified_risks', 'compliance_impact']
            
            preview = {
                'project_name': project_context['project_name'],
                'total_findings': len(findings_data),
                'sections_to_complete': sections,
                'risk_distribution': {},
                'frameworks': project_context.get('compliance_frameworks', [])
            }
            
            # Risk distribution
            for finding in findings_data:
                risk = finding.get('risk', 'Unknown').lower()
                preview['risk_distribution'][risk] = preview['risk_distribution'].get(risk, 0) + 1
            
            return preview
            
        except Exception as e:
            return {'error': str(e)}