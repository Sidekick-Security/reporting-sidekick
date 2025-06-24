#!/usr/bin/env python3

import os
import requests
import json
from lib.parsers.nessus_parser import NessusParser
from lib.parsers.nuclei_parser import NucleiParser

class VulnImportProcessor:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.nessus_parser = NessusParser()
        self.nuclei_parser = NucleiParser()
        
        # Load API configuration
        try:
            import sys
            sys.path.append(os.path.join(os.path.dirname(__file__), '../../conf'))
            import conf
            self.api_url = conf.sysreptorAPIUrl
            self.api_headers = {'Authorization': conf.sysreptorAPI.replace('Authorization: ', '')}
        except ImportError:
            raise Exception("Could not load SysReptor API configuration from conf/conf.py")
    
    def check_against_sysreptor(self, nessus_dir, nuclei_dir):
        """Check vulnerability scan results against SysReptor finding templates"""
        try:
            if self.verbose:
                print("Starting SysReptor template comparison...")
            
            # Parse scan results
            scan_findings = self._parse_scan_results(nessus_dir, nuclei_dir)
            if self.verbose:
                print(f"Found {len(scan_findings)} total scan findings")
            
            # Get SysReptor templates with VulnerabilityScanning tag
            sysreptor_templates = self._get_vulnerability_scanning_templates()
            if self.verbose:
                print(f"Found {len(sysreptor_templates)} SysReptor templates with 'VulnerabilityScanning' tag")
            
            # Compare findings against templates
            matched_findings, unmatched_findings = self._compare_findings(scan_findings, sysreptor_templates)
            
            # Display results
            self._display_results(matched_findings, unmatched_findings)
            
            # If there are unmatched findings, prompt user for import
            if unmatched_findings:
                self._prompt_for_import(unmatched_findings)
            
        except Exception as e:
            raise Exception(f"Error checking against SysReptor: {str(e)}")
    
    def _parse_scan_results(self, nessus_dir, nuclei_dir):
        """Parse Nessus and Nuclei scan results"""
        all_findings = []
        
        # Parse Nessus files
        if self.verbose:
            print(f"Parsing Nessus files from: {nessus_dir}")
        
        if not os.path.exists(nessus_dir):
            raise Exception(f"Nessus directory '{nessus_dir}' does not exist")
        
        nessus_files = [f for f in os.listdir(nessus_dir) if f.endswith('.nessus')]
        if self.verbose:
            print(f"Found {len(nessus_files)} .nessus files")
        
        for nessus_file in nessus_files:
            file_path = os.path.join(nessus_dir, nessus_file)
            if self.verbose:
                print(f"Parsing: {file_path}")
            try:
                nessus_findings = self.nessus_parser.parse_file(file_path)
                all_findings.extend(nessus_findings)
                if self.verbose:
                    print(f"Found {len(nessus_findings)} Nessus findings")
            except Exception as e:
                print(f"Error parsing {file_path}: {str(e)}")
        
        # Parse Nuclei files
        if self.verbose:
            print(f"Parsing Nuclei files from: {nuclei_dir}")
        
        if not os.path.exists(nuclei_dir):
            raise Exception(f"Nuclei directory '{nuclei_dir}' does not exist")
        
        nuclei_files = [f for f in os.listdir(nuclei_dir) if f.endswith(('.json', '.txt'))]
        json_files = [f for f in nuclei_files if f.endswith('.json')]
        txt_files = [f for f in nuclei_files if f.endswith('.txt')]
        
        if self.verbose:
            print(f"Found {len(json_files)} .json files and {len(txt_files)} .txt files")
        
        for nuclei_file in nuclei_files:
            file_path = os.path.join(nuclei_dir, nuclei_file)
            if self.verbose:
                print(f"Parsing: {file_path}")
            try:
                nuclei_findings = self.nuclei_parser.parse_file(file_path)
                all_findings.extend(nuclei_findings)
                if self.verbose:
                    print(f"Found {len(nuclei_findings)} Nuclei findings")
            except Exception as e:
                print(f"Error parsing {file_path}: {str(e)}")
        
        # Filter out informational findings - only check Low severity and higher
        filtered_findings = self._filter_findings_by_severity(all_findings)
        
        # Remove duplicate titles - keep only unique vulnerability titles
        deduplicated_findings = self._remove_duplicate_titles(filtered_findings)
        
        if self.verbose:
            filtered_count = len(all_findings) - len(filtered_findings)
            duplicate_count = len(filtered_findings) - len(deduplicated_findings)
            print(f"Filtered out {filtered_count} informational findings: {len(all_findings)} -> {len(filtered_findings)}")
            print(f"Removed {duplicate_count} duplicate titles: {len(filtered_findings)} -> {len(deduplicated_findings)}")
        
        return deduplicated_findings
    
    def _filter_findings_by_severity(self, findings):
        """Filter out informational findings, keep Low severity and higher"""
        filtered_findings = []
        
        for finding in findings:
            risk = finding.get('risk', '').lower()
            # Keep Critical, High, Medium, Low - exclude Informational
            if risk in ['critical', 'high', 'medium', 'low']:
                filtered_findings.append(finding)
        
        return filtered_findings
    
    def _remove_duplicate_titles(self, findings):
        """Remove duplicate vulnerability titles, keeping only unique ones"""
        seen_titles = set()
        unique_findings = []
        
        for finding in findings:
            title = finding.get('title', '').lower().strip()
            if title and title not in seen_titles:
                seen_titles.add(title)
                unique_findings.append(finding)
        
        return unique_findings
    
    def _sort_findings_by_severity(self, findings):
        """Sort findings by severity: Critical -> High -> Medium -> Low"""
        severity_order = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        
        def get_severity_priority(finding):
            risk = finding.get('risk', 'low').lower()
            return severity_order.get(risk, 0)
        
        return sorted(findings, key=get_severity_priority, reverse=True)
    
    def _get_vulnerability_scanning_templates(self):
        """Fetch SysReptor finding templates with VulnerabilityScanning tag"""
        try:
            url = f"{self.api_url}findingtemplates"
            if self.verbose:
                print(f"Fetching templates from: {url}")
            
            response = requests.get(url, headers=self.api_headers)
            response.raise_for_status()
            
            data = response.json()
            templates = data.get('results', [])
            
            # Filter templates with VulnerabilityScanning tag (case insensitive)
            vuln_scan_templates = []
            for template in templates:
                tags = [tag.lower() for tag in template.get('tags', [])]
                if 'vulnerabilityscanning' in tags:
                    vuln_scan_templates.append(template)
            
            return vuln_scan_templates
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to fetch SysReptor templates: {str(e)}")
        except Exception as e:
            raise Exception(f"Error processing SysReptor response: {str(e)}")
    
    def _compare_findings(self, scan_findings, sysreptor_templates):
        """Compare scan findings against SysReptor template titles"""
        matched_findings = []
        unmatched_findings = []
        
        # Extract template titles for comparison
        template_titles = []
        for template in sysreptor_templates:
            for translation in template.get('translations', []):
                if translation.get('is_main', False):
                    title = translation.get('data', {}).get('title', '')
                    if title:
                        template_titles.append(title.lower())
        
        if self.verbose:
            print(f"Comparing against {len(template_titles)} template titles")
        
        # Compare each finding
        for finding in scan_findings:
            finding_title = finding.get('title', '').lower()
            
            # Check for exact match or partial match
            matched = False
            for template_title in template_titles:
                if self._titles_match(finding_title, template_title):
                    matched_findings.append({
                        'finding': finding,
                        'matched_template': template_title
                    })
                    matched = True
                    break
            
            if not matched:
                unmatched_findings.append(finding)
        
        return matched_findings, unmatched_findings
    
    def _titles_match(self, finding_title, template_title):
        """Check if finding title matches template title"""
        # Exact match
        if finding_title == template_title:
            return True
        
        # Partial match - check if core keywords match
        finding_words = set(finding_title.lower().split())
        template_words = set(template_title.lower().split())
        
        # Remove common words that don't add meaning
        stop_words = {'the', 'a', 'an', 'and', 'or', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        finding_words -= stop_words
        template_words -= stop_words
        
        # Check if there's significant overlap
        if len(finding_words) > 0 and len(template_words) > 0:
            overlap = len(finding_words.intersection(template_words))
            min_length = min(len(finding_words), len(template_words))
            
            # Require at least 60% word overlap
            if overlap / min_length >= 0.6:
                return True
        
        return False
    
    def _display_results(self, matched_findings, unmatched_findings):
        """Display comparison results"""
        total_findings = len(matched_findings) + len(unmatched_findings)
        
        print(f"\n=== SysReptor Template Comparison Results ===")
        print(f"Total scan findings: {total_findings}")
        print(f"{len(matched_findings)} findings already exist in SysReptor")
        print(f"{len(unmatched_findings)} new findings not found in SysReptor")
        
        if self.verbose and matched_findings:
            print(f"\n--- Matched Findings ---")
            for match in matched_findings[:10]:  # Show first 10
                finding = match['finding']
                template = match['matched_template']
                print(f"  • {finding.get('title', 'Unknown')} -> {template}")
            if len(matched_findings) > 10:
                print(f"  ... and {len(matched_findings) - 10} more matches")
        
        if self.verbose and unmatched_findings:
            print(f"\n--- Unmatched Findings (New) ---")
            for finding in unmatched_findings[:10]:  # Show first 10
                print(f"  • {finding.get('title', 'Unknown')} [{finding.get('risk', 'Unknown')}]")
            if len(unmatched_findings) > 10:
                print(f"  ... and {len(unmatched_findings) - 10} more unmatched findings")
        
        print(f"\n=== End Results ===")
    
    def _prompt_for_import(self, unmatched_findings):
        """Prompt user to select findings for import into SysReptor"""
        print(f"\n=== Findings Available for Import ===")
        print("The following findings are not in SysReptor and can be imported as templates:")
        print()
        
        # Sort findings by severity (Critical -> High -> Medium -> Low)
        sorted_findings = self._sort_findings_by_severity(unmatched_findings)
        
        # Display numbered list of sorted unmatched findings
        for i, finding in enumerate(sorted_findings, 1):
            title = finding.get('title', 'Unknown')
            risk = finding.get('risk', 'Unknown')
            host = finding.get('host', 'Unknown')
            print(f"{i:2d}. {title} [{risk}] - {host}")
        
        # Update the unmatched_findings to use sorted order for selection
        unmatched_findings[:] = sorted_findings
        
        print()
        print("Enter the numbers of findings to import (e.g., 1,3,5-7,10):")
        print("Press Enter to skip import, or 'all' to import all findings")
        
        try:
            user_input = input("Selection: ").strip()
            
            if not user_input:
                print("Import cancelled.")
                return
            
            if user_input.lower() == 'all':
                selected_findings = unmatched_findings
            else:
                selected_indices = self._parse_selection(user_input, len(unmatched_findings))
                selected_findings = [unmatched_findings[i-1] for i in selected_indices]
            
            if selected_findings:
                print(f"\nImporting {len(selected_findings)} findings to SysReptor...")
                self._import_findings_to_sysreptor(selected_findings)
            else:
                print("No valid selections made.")
                
        except KeyboardInterrupt:
            print("\nImport cancelled by user.")
        except Exception as e:
            print(f"Error during import selection: {str(e)}")
    
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
    
    def _import_findings_to_sysreptor(self, findings):
        """Import selected findings to SysReptor as finding templates"""
        successful_imports = 0
        failed_imports = 0
        
        for finding in findings:
            try:
                # Create finding template payload
                template_data = self._create_template_payload(finding)
                
                # POST to SysReptor API
                url = f"{self.api_url}findingtemplates"
                response = requests.post(url, headers=self.api_headers, json=template_data)
                response.raise_for_status()
                
                successful_imports += 1
                if self.verbose:
                    print(f"  ✓ Imported: {finding.get('title', 'Unknown')}")
                
            except Exception as e:
                failed_imports += 1
                print(f"  ✗ Failed to import '{finding.get('title', 'Unknown')}': {str(e)}")
        
        print(f"\nImport Summary:")
        print(f"Successfully imported: {successful_imports}")
        if failed_imports > 0:
            print(f"Failed imports: {failed_imports}")
        print(f"Total processed: {len(findings)}")
    
    def _create_template_payload(self, finding):
        """Create SysReptor finding template payload from scan finding"""
        # Use actual CVSS score from scan if available, otherwise fall back to risk mapping
        actual_cvss = finding.get('cvss_score', '')
        
        if actual_cvss and actual_cvss.replace('.', '').isdigit():
            cvss_score = float(actual_cvss)
        else:
            # Map risk levels to CVSS scores as fallback
            risk_to_cvss = {
                'critical': 9.5,
                'high': 7.5, 
                'medium': 5.5,
                'low': 3.5
            }
            risk_level = finding.get('risk', 'low').lower()
            cvss_score = risk_to_cvss.get(risk_level, 3.5)
        
        risk_level = finding.get('risk', 'low').lower()
        
        # Create the template structure
        template_data = {
            "source": "created",
            "tags": ["vulnerabilityScanning"],
            "translations": [
                {
                    "language": "en-US",
                    "status": "in-progress",
                    "is_main": True,
                    "risk_score": cvss_score,
                    "risk_level": risk_level,
                    "data": {
                        "title": finding.get('title', 'Unknown Vulnerability'),
                        "risk_description": finding.get('description', 'Vulnerability identified during security scan'),
                        "recommendation": finding.get('solution', 'Review and remediate this vulnerability'),
                        "affected_components": [],
                        "retest_status": "open",
                        "cvss_number": cvss_score,
                        "risk_rating": risk_level.title()
                    }
                }
            ]
        }
        
        return template_data