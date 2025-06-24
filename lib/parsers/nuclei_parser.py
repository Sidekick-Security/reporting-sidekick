#!/usr/bin/env python3

import json
import os
import glob
from pathlib import Path

class NucleiParser:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.severity_mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Informational',
            'informational': 'Informational'
        }
        
    def parse_directory(self, directory_path):
        findings = []
        # Look for both .json and .txt files (nuclei often outputs to .txt in JSONL format)
        json_files = glob.glob(os.path.join(directory_path, "*.json"))
        txt_files = glob.glob(os.path.join(directory_path, "*.txt"))
        all_files = json_files + txt_files
        
        if self.verbose:
            print(f"Found {len(json_files)} .json files and {len(txt_files)} .txt files")
        
        for file_path in all_files:
            if self.verbose:
                print(f"Parsing: {file_path}")
            try:
                findings.extend(self.parse_file(file_path))
            except Exception as e:
                print(f"Error parsing {file_path}: {str(e)}")
                
        return findings
    
    def parse_file(self, file_path):
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
            # Handle both single JSON objects and JSONL (JSON Lines) format
            if content.startswith('['):
                # Standard JSON array
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        finding = self._parse_nuclei_finding(item, file_path)
                        if finding:
                            findings.append(finding)
                else:
                    finding = self._parse_nuclei_finding(data, file_path)
                    if finding:
                        findings.append(finding)
            else:
                # JSONL format (one JSON object per line)
                for line_num, line in enumerate(content.split('\n'), 1):
                    line = line.strip()
                    if line:
                        try:
                            item = json.loads(line)
                            finding = self._parse_nuclei_finding(item, file_path)
                            if finding:
                                findings.append(finding)
                        except json.JSONDecodeError as e:
                            if self.verbose:
                                print(f"Error parsing line {line_num} in {file_path}: {str(e)}")
                            continue
                            
        except json.JSONDecodeError as e:
            raise Exception(f"JSON parsing error in {file_path}: {str(e)}")
        except Exception as e:
            raise Exception(f"Error processing {file_path}: {str(e)}")
            
        return findings
    
    def _parse_nuclei_finding(self, item, source_file):
        if not isinstance(item, dict):
            return None
            
        # Extract basic information
        template_id = item.get('template-id', item.get('templateID', ''))
        template_name = item.get('template', template_id)
        host = item.get('host', '')
        matched_at = item.get('matched-at', item.get('matched_at', host))
        
        # Extract IP address (if available)
        ip_address = item.get('ip', '')
        
        # Extract template info
        info = item.get('info', {})
        if not isinstance(info, dict):
            info = {}
            
        name = info.get('name', template_name)
        severity = info.get('severity', 'low').lower()
        description = info.get('description', '')
        reference = info.get('reference', [])
        tags = info.get('tags', [])
        
        # Handle different reference formats
        if isinstance(reference, str):
            reference = [reference]
        elif not isinstance(reference, list):
            reference = []
            
        # Handle different tags formats
        if isinstance(tags, str):
            tags = [tags]
        elif not isinstance(tags, list):
            tags = []
            
        # Extract CVE references from tags or references
        cve_refs = []
        for tag in tags:
            if isinstance(tag, str) and tag.lower().startswith('cve-'):
                cve_refs.append(tag.upper())
        for ref in reference:
            if isinstance(ref, str) and 'cve' in ref.lower():
                cve_refs.append(ref)
                
        # Get risk level
        risk = self.severity_mapping.get(severity, 'Low')
        
        # Extract URL/port information
        url_info = self._extract_url_info(matched_at or host)
        
        # Use IP address if available, otherwise fall back to parsed host
        final_host_ip = ip_address if ip_address else url_info['host']
        
        # Extract hostname from URL if available
        hostname = self._extract_hostname(matched_at or host)
        
        # Extract matcher information for additional context
        matcher_name = ''
        extracted_data = ''
        if 'matcher-name' in item:
            matcher_name = item['matcher-name']
        if 'extracted-results' in item:
            extracted_results = item['extracted-results']
            if isinstance(extracted_results, list):
                extracted_data = ', '.join(str(x) for x in extracted_results)
            else:
                extracted_data = str(extracted_results)
        
        # Build description
        full_description = description
        if extracted_data:
            full_description += f"\n\nExtracted data: {extracted_data}"
        if matcher_name:
            full_description += f"\n\nMatcher: {matcher_name}"
            
        # Build solution based on template type and severity
        solution = self._generate_solution(template_id, name, severity, info)
        
        finding = {
            'source': 'Nuclei',
            'source_file': os.path.basename(source_file),
            'host': final_host_ip,
            'hostname': hostname,
            'port': url_info['port'],
            'protocol': url_info['protocol'],
            'service': url_info['service'],
            'risk': risk,
            'title': name or f"Nuclei Detection: {template_id}",
            'description': full_description.strip(),
            'solution': solution,
            'see_also': ', '.join(reference),
            'cvss_score': '',  # Nuclei doesn't typically provide CVSS scores
            'cvss_vector': '',
            'cve_references': ', '.join(cve_refs),
            'vulnerability_type': self._categorize_vulnerability(template_id, tags),
            'matched_at': matched_at,
            'tags': ', '.join(tags)
        }
        
        return finding
    
    def _extract_url_info(self, url_or_host):
        info = {
            'host': '',
            'port': '',
            'protocol': 'tcp',
            'service': ''
        }
        
        if not url_or_host:
            return info
            
        # Handle URL format
        if '://' in url_or_host:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url_or_host)
                info['host'] = parsed.hostname or parsed.netloc.split(':')[0]
                info['port'] = str(parsed.port) if parsed.port else ''
                
                if parsed.scheme == 'https':
                    info['service'] = 'https'
                    if not info['port']:
                        info['port'] = '443'
                elif parsed.scheme == 'http':
                    info['service'] = 'http'
                    if not info['port']:
                        info['port'] = '80'
                elif parsed.scheme == 'ftp':
                    info['service'] = 'ftp'
                    if not info['port']:
                        info['port'] = '21'
                else:
                    info['service'] = parsed.scheme
                    
            except Exception:
                # Fallback to simple parsing
                info['host'] = url_or_host
        else:
            # Handle host:port format
            if ':' in url_or_host:
                parts = url_or_host.split(':')
                info['host'] = parts[0]
                if len(parts) > 1 and parts[1].isdigit():
                    info['port'] = parts[1]
            else:
                info['host'] = url_or_host
                
        return info
    
    def _extract_hostname(self, url_or_host):
        """Extract hostname from URL or host string"""
        if not url_or_host:
            return ''
            
        # Handle URL format
        if '://' in url_or_host:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url_or_host)
                hostname = parsed.hostname
                if hostname:
                    # If it's not an IP address, return the hostname
                    import ipaddress
                    try:
                        ipaddress.ip_address(hostname)
                        # It's an IP address, return empty hostname
                        return ''
                    except ValueError:
                        # It's a hostname, return it
                        return hostname
            except Exception:
                pass
        else:
            # Handle host:port format - check if it's a hostname (not IP)
            host_part = url_or_host.split(':')[0] if ':' in url_or_host else url_or_host
            try:
                import ipaddress
                ipaddress.ip_address(host_part)
                # It's an IP address, return empty hostname
                return ''
            except ValueError:
                # It's likely a hostname, return it
                return host_part
                
        return ''
    
    def _categorize_vulnerability(self, template_id, tags):
        # Categorize based on template ID and tags
        template_lower = template_id.lower()
        tag_string = ' '.join(tags).lower() if tags else ''
        
        if any(keyword in template_lower for keyword in ['xss', 'injection', 'sqli', 'sql']):
            return 'Web Application'
        elif any(keyword in template_lower for keyword in ['cve-', 'rce', 'remote']):
            return 'Remote Code Execution'
        elif any(keyword in template_lower for keyword in ['lfi', 'rfi', 'file-read', 'path-traversal']):
            return 'File Inclusion/Path Traversal'
        elif any(keyword in template_lower for keyword in ['config', 'exposure', 'disclosure']):
            return 'Information Disclosure'
        elif any(keyword in template_lower for keyword in ['auth', 'login', 'bypass']):
            return 'Authentication Issue'
        elif any(keyword in template_lower for keyword in ['dos', 'denial']):
            return 'Denial of Service'
        elif any(keyword in tag_string for keyword in ['network', 'tcp', 'udp']):
            return 'Network Service'
        else:
            return 'Web Application'
    
    def _generate_solution(self, template_id, name, severity, info):
        # Generate contextual remediation advice
        template_lower = template_id.lower()
        
        if 'cve-' in template_lower:
            return "Apply the latest security patches and updates for the affected software component. Review vendor security advisories for specific remediation steps."
        elif any(keyword in template_lower for keyword in ['xss', 'injection']):
            return "Implement proper input validation and output encoding. Use parameterized queries and sanitize user input to prevent injection attacks."
        elif any(keyword in template_lower for keyword in ['config', 'exposure']):
            return "Review and secure configuration files. Ensure sensitive information is not exposed publicly and implement proper access controls."
        elif any(keyword in template_lower for keyword in ['auth', 'login']):
            return "Strengthen authentication mechanisms. Implement multi-factor authentication and review access controls."
        elif any(keyword in template_lower for keyword in ['file-read', 'lfi', 'path-traversal']):
            return "Implement proper file access controls and input validation. Restrict file system access and validate file paths."
        elif severity in ['critical', 'high']:
            return "This is a high-priority vulnerability that requires immediate attention. Review the specific finding details and apply appropriate security controls."
        else:
            return "Review the vulnerability details and implement appropriate security controls. Consider updating affected software and reviewing security configurations."
    
    def _risk_to_severity(self, risk):
        risk_map = {
            'Critical': '4',
            'High': '3', 
            'Medium': '2',
            'Low': '1',
            'Informational': '0'
        }
        return risk_map.get(risk, '1')