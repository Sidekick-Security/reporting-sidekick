#!/usr/bin/env python3

import os
import sys
import requests
import json
from ..parsers.nessus_parser import NessusParser
from ..parsers.nuclei_parser import NucleiParser
from ..generators.xlsx_generator import XLSXGenerator

class VulnScanProcessor:
    def __init__(self, verbose=False):
        self.verbose = verbose
        
        # Load API configuration
        try:
            import sys
            sys.path.append(os.path.join(os.path.dirname(__file__), '../../conf'))
            import conf
            self.api_url = conf.sysreptorAPIUrl
            self.api_headers = {'Authorization': conf.sysreptorAPI.replace('Authorization: ', '')}
        except ImportError:
            if self.verbose:
                print("Warning: Could not load SysReptor API configuration - SysReptor integration disabled")
            self.api_url = None
            self.api_headers = None
        
    def process_scans(self, nessus_dir, nuclei_dir, output_file, debug_mode=False):
        """
        Process vulnerability scans from Nessus and Nuclei directories and generate XLSX report
        
        Args:
            nessus_dir (str): Directory containing Nessus .nessus files
            nuclei_dir (str): Directory containing Nuclei .json/.txt files  
            output_file (str): Output XLSX filename
            debug_mode (bool): Enable debug mode with additional columns
        """
        
        # Validate directories exist
        if not os.path.isdir(nessus_dir):
            raise Exception(f"Nessus directory '{nessus_dir}' does not exist")
        
        if not os.path.isdir(nuclei_dir):
            raise Exception(f"Nuclei directory '{nuclei_dir}' does not exist")
        
        # Validate output directory exists or can be created
        output_dir = os.path.dirname(os.path.abspath(output_file))
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
                if self.verbose:
                    print(f"Created output directory: {output_dir}")
            except Exception as e:
                raise Exception(f"Cannot create output directory '{output_dir}': {str(e)}")
        
        # Validate we can write to output file location
        try:
            with open(output_file, 'w') as test_file:
                pass
            os.remove(output_file)  # Clean up test file
        except Exception as e:
            raise Exception(f"Cannot write to output file '{output_file}': {str(e)}")

        try:
            # Initialize parsers
            nessus_parser = NessusParser(verbose=self.verbose)
            nuclei_parser = NucleiParser(verbose=self.verbose)
            
            if self.verbose:
                print(f"Parsing Nessus files from: {nessus_dir}")
            
            # Parse Nessus files
            nessus_findings = nessus_parser.parse_directory(nessus_dir)
            
            if self.verbose:
                print(f"Found {len(nessus_findings)} Nessus findings")
                print(f"Parsing Nuclei files from: {nuclei_dir}")
            
            # Parse Nuclei files
            nuclei_findings = nuclei_parser.parse_directory(nuclei_dir)
            
            if self.verbose:
                print(f"Found {len(nuclei_findings)} Nuclei findings")
            
            # Combine findings
            all_findings = nessus_findings + nuclei_findings
            
            # Filter out informational findings and duplicates
            filtered_findings = self._filter_and_deduplicate_findings(all_findings)
            
            if self.verbose:
                print(f"Filtered out informational findings: {len(all_findings)} -> {len(filtered_findings)}")
            
            if not filtered_findings:
                print("Warning: No findings to report after filtering informational items")
                return
            
            # Prompt user to select findings for the report
            selected_findings = self._prompt_for_finding_selection(filtered_findings)
            
            if not selected_findings:
                print("No findings selected for report generation.")
                return
            
            # Enrich selected findings with SysReptor data if available
            enriched_findings = self._enrich_findings_with_sysreptor(selected_findings)
            
            # Generate XLSX report
            xlsx_generator = XLSXGenerator(verbose=self.verbose)
            xlsx_generator.generate_report(enriched_findings, output_file, debug_mode=debug_mode)
            
            print(f"Report generated successfully: {output_file}")
            print(f"Total findings: {len(enriched_findings)}")
            
        except Exception as e:
            raise Exception(f"Error processing vulnerability scans: {str(e)}")
    
    def _filter_and_deduplicate_findings(self, findings):
        """Filter out informational findings and remove duplicates"""
        # Filter out informational findings
        filtered = [f for f in findings if f.get('risk', '').lower() != 'informational']
        
        # Remove duplicates by title + host combination (unique instances)
        seen_instances = set()
        unique_findings = []
        
        for finding in filtered:
            title = finding.get('title', '').lower().strip()
            host = finding.get('host', '').strip()
            
            # Create unique identifier for this vulnerability instance
            instance_key = f"{title}|{host}"
            
            if instance_key and instance_key not in seen_instances:
                seen_instances.add(instance_key)
                unique_findings.append(finding)
        
        return unique_findings
    
    def _prompt_for_finding_selection(self, findings):
        """Prompt user to select findings for the report"""
        print(f"\n=== Vulnerability Findings Available for Report ===")
        print("The following vulnerabilities were found in the scans:")
        print()
        
        # Sort findings by severity (Critical -> High -> Medium -> Low)
        sorted_findings = self._sort_findings_by_severity(findings)
        
        # Display numbered list of findings
        for i, finding in enumerate(sorted_findings, 1):
            title = finding.get('title', 'Unknown')
            risk = finding.get('risk', 'Unknown')
            host = finding.get('host', 'Unknown')
            print(f"{i:2d}. {title} [{risk}] - {host}")
        
        print()
        print("Enter the numbers of findings to include in the report (e.g., 1,3,5-7,10):")
        print("Press Enter to include all findings, or 'q' to quit")
        
        try:
            user_input = input("Selection: ").strip()
            
            if user_input.lower() == 'q':
                return []
            
            if not user_input:
                return sorted_findings
            
            selected_indices = self._parse_selection(user_input, len(sorted_findings))
            selected_findings = [sorted_findings[i-1] for i in selected_indices]
            
            print(f"\nSelected {len(selected_findings)} findings for the report.")
            return selected_findings
                
        except KeyboardInterrupt:
            print("\nReport generation cancelled by user.")
            return []
        except Exception as e:
            print(f"Error during selection: {str(e)}")
            return []
    
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
    
    def _enrich_findings_with_sysreptor(self, findings):
        """Enrich findings with SysReptor template data where available"""
        if not self.api_url or not self.api_headers:
            if self.verbose:
                print("SysReptor API not configured - using scan data only")
            return findings
        
        try:
            # Get SysReptor templates
            sysreptor_templates = self._get_sysreptor_templates()
            
            if self.verbose:
                print(f"Found {len(sysreptor_templates)} SysReptor templates")
            
            # Match findings with templates and enrich
            enriched_findings = []
            matched_count = 0
            
            for finding in findings:
                enriched_finding = finding.copy()
                
                # Try to find matching template
                match_result = self._find_matching_template(finding, sysreptor_templates)
                
                if match_result:
                    matching_template, template_id = match_result
                    
                    # Fetch detailed template data to get modified_title and recommendation
                    detailed_template = self._get_detailed_template(template_id)
                    
                    # Enrich with SysReptor data
                    enriched_finding = self._merge_sysreptor_data(finding, detailed_template or matching_template)
                    matched_count += 1
                    
                    if self.verbose:
                        original_title = finding.get('title', 'Unknown')
                        new_title = enriched_finding.get('title', 'Unknown')
                        print(f"  ✓ Enriched: {original_title}")
                        if original_title != new_title:
                            print(f"    → Title changed to: {new_title}")
                        if detailed_template:
                            template_data = detailed_template.get('data', {})
                            if template_data.get('modified_title'):
                                print(f"    → Found modified_title: {template_data.get('modified_title')}")
                            if template_data.get('recommendation'):
                                print(f"    → Found recommendation: {template_data.get('recommendation')[:100]}...")
                
                enriched_findings.append(enriched_finding)
            
            print(f"\nEnriched {matched_count} findings with SysReptor template data")
            print(f"Using scan data only for {len(findings) - matched_count} findings")
            
            return enriched_findings
            
        except Exception as e:
            print(f"Warning: Error enriching with SysReptor data: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return findings
    
    def _get_sysreptor_templates(self):
        """Fetch all SysReptor finding templates"""
        try:
            url = f"{self.api_url}findingtemplates"
            response = requests.get(url, headers=self.api_headers)
            response.raise_for_status()
            
            data = response.json()
            return data.get('results', [])
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to fetch SysReptor templates: {str(e)}")
    
    def _get_detailed_template(self, template_id):
        """Fetch detailed template data from SysReptor to get modified_title and recommendation"""
        try:
            url = f"{self.api_url}findingtemplates/{template_id}"
            if self.verbose:
                print(f"    → Fetching detailed template data from: {url}")
            
            response = requests.get(url, headers=self.api_headers)
            response.raise_for_status()
            
            template_data = response.json()
            
            # Find the main translation
            for translation in template_data.get('translations', []):
                if translation.get('is_main', False):
                    return translation
                    
            return None
            
        except Exception as e:
            if self.verbose:
                print(f"    → Warning: Could not fetch detailed template data: {str(e)}")
            return None
    
    def _find_matching_template(self, finding, templates):
        """Find matching SysReptor template for a finding - returns (translation, template_id) or None"""
        finding_title = finding.get('title', '').lower().strip()
        
        if self.verbose and finding_title == "cgi generic html injections (quick test)":
            print(f"\n  DEBUG: Looking for match for: '{finding_title}'")
        
        for template in templates:
            template_id = template.get('id')
            for translation in template.get('translations', []):
                if translation.get('is_main', False):
                    template_title = translation.get('data', {}).get('title', '').lower().strip()
                    
                    if self.verbose and finding_title == "cgi generic html injections (quick test)":
                        print(f"  DEBUG: Checking against template: '{template_title}'")
                    
                    if self._titles_match(finding_title, template_title):
                        if self.verbose and finding_title == "cgi generic html injections (quick test)":
                            print(f"  DEBUG: MATCH FOUND!")
                            template_data = translation.get('data', {})
                            print(f"  DEBUG: Template data keys: {list(template_data.keys())}")
                        return translation, template_id
        
        if self.verbose and finding_title == "cgi generic html injections (quick test)":
            print(f"  DEBUG: No match found for '{finding_title}'")
        
        return None
    
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
    
    def _merge_sysreptor_data(self, finding, template):
        """Merge SysReptor template data with scan finding data - prioritize SysReptor values as known good"""
        enriched = finding.copy()
        template_data = template.get('data', {})
        
        # Always keep scan data for technical details (host, port, protocol, service, source info)
        # These come from the actual scan and should not be overridden
        
        # Use SysReptor title (modified_title or title) if available and not blank
        if template_data.get('modified_title') and str(template_data.get('modified_title')).strip():
            enriched['title'] = template_data['modified_title']
        elif template_data.get('title') and str(template_data.get('title')).strip():
            enriched['title'] = template_data['title']
        
        # Use SysReptor description (risk_description) if available and not blank
        if template_data.get('risk_description') and str(template_data.get('risk_description')).strip():
            enriched['description'] = template_data['risk_description']
        
        # Use SysReptor solution (recommendation) if available and not blank
        if template_data.get('recommendation') and str(template_data.get('recommendation')).strip():
            enriched['solution'] = template_data['recommendation']
        
        # Use SysReptor risk level if available and not blank
        if template.get('risk_level') and str(template.get('risk_level')).strip():
            enriched['risk'] = template['risk_level'].title()
        elif template_data.get('risk_rating') and str(template_data.get('risk_rating')).strip():
            enriched['risk'] = template_data['risk_rating']
        
        # Use SysReptor CVSS score if available and not blank/zero
        if template.get('risk_score') is not None and template.get('risk_score') != 0:
            enriched['cvss_score'] = template['risk_score']
        elif template_data.get('cvss_number') is not None and template_data.get('cvss_number') != 0:
            enriched['cvss_score'] = template_data['cvss_number']
        
        # Use SysReptor vulnerability type if available and not blank
        if template_data.get('vulnerability_type') and str(template_data.get('vulnerability_type')).strip():
            enriched['vulnerability_type'] = template_data['vulnerability_type']
        
        # Use SysReptor CVE references if available and not blank
        if template_data.get('cve_references') and str(template_data.get('cve_references')).strip():
            enriched['cve_references'] = template_data['cve_references']
        
        # Use SysReptor CVSS vector if available and not blank
        if template_data.get('cvss_vector') and str(template_data.get('cvss_vector')).strip():
            enriched['cvss_vector'] = template_data['cvss_vector']
        
        # Use SysReptor see_also/references if available and not blank
        if template_data.get('references') and str(template_data.get('references')).strip():
            enriched['see_also'] = template_data['references']
        elif template_data.get('external_references') and str(template_data.get('external_references')).strip():
            enriched['see_also'] = template_data['external_references']
        
        # EXCEPTION: affected_components should always come from scan data, never from SysReptor
        # This ensures we capture the actual affected hosts/ports from the scan
        # (SysReptor affected_components is template-level, scan data is instance-specific)
        
        if self.verbose:
            # Log what SysReptor fields were applied
            sysreptor_fields = []
            if template_data.get('modified_title') or template_data.get('title'):
                sysreptor_fields.append('title')
            if template_data.get('risk_description'):
                sysreptor_fields.append('description')
            if template_data.get('recommendation'):
                sysreptor_fields.append('recommendation')
            if template.get('risk_level') or template_data.get('risk_rating'):
                sysreptor_fields.append('risk_level')
            if template.get('risk_score') or template_data.get('cvss_number'):
                sysreptor_fields.append('cvss_score')
            
            if sysreptor_fields:
                print(f"    → Applied SysReptor fields: {', '.join(sysreptor_fields)}")
        
        return enriched

    def get_statistics(self, nessus_dir, nuclei_dir):
        """
        Get statistics about scan files without processing them
        
        Args:
            nessus_dir (str): Directory containing Nessus .nessus files
            nuclei_dir (str): Directory containing Nuclei .json/.txt files
            
        Returns:
            dict: Statistics about the scan files
        """
        stats = {
            'nessus_files': 0,
            'nuclei_files': 0,
            'total_findings': 0,
            'actionable_findings': 0
        }
        
        try:
            if os.path.isdir(nessus_dir):
                import glob
                nessus_files = glob.glob(os.path.join(nessus_dir, "*.nessus"))
                stats['nessus_files'] = len(nessus_files)
            
            if os.path.isdir(nuclei_dir):
                import glob
                json_files = glob.glob(os.path.join(nuclei_dir, "*.json"))
                txt_files = glob.glob(os.path.join(nuclei_dir, "*.txt"))
                stats['nuclei_files'] = len(json_files) + len(txt_files)
                
        except Exception as e:
            if self.verbose:
                print(f"Error getting statistics: {str(e)}")
                
        return stats