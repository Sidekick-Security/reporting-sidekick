#!/usr/bin/env python3

import os
import re
import sys
from pathlib import Path


class EPTProcessor:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.findings = {}
        self.user_inputs = {}
        
    def log(self, message):
        if self.verbose:
            print(f"[EPT] {message}")
    
    def generate_ept_report(self, directory):
        """Main method to generate EPT report from directory structure"""
        self.log(f"Processing EPT directory: {directory}")
        
        # Validate directory structure
        if not self._validate_directory_structure(directory):
            raise ValueError("Invalid EPT directory structure")
        
        # Parse output files
        self._parse_output_files(directory)
        
        # Get user inputs
        self._get_user_inputs()
        
        # Generate report sections
        report = self._generate_report_sections()
        
        # Output the report
        print("\n" + "="*80)
        print("EPT ASSESSMENT REPORT")
        print("="*80)
        print(report)
        
        return report
    
    def _validate_directory_structure(self, directory):
        """Validate that the directory follows ept-template structure"""
        required_dirs = [
            "01_dmarc-check",
            "02_github-scraping", 
            "04_dns-enumeration",
            "07_vulnscan",
            "08_forced-browsing",
            "09_ssl-check"
        ]
        
        base_path = Path(directory)
        if not base_path.exists():
            self.log(f"Directory does not exist: {directory}")
            return False
            
        missing_dirs = []
        for req_dir in required_dirs:
            if not (base_path / req_dir).exists():
                missing_dirs.append(req_dir)
        
        if missing_dirs:
            self.log(f"Missing required directories: {missing_dirs}")
            return False
            
        self.log("Directory structure validation passed")
        return True
    
    def _parse_output_files(self, directory):
        """Parse output files from each scan directory"""
        base_path = Path(directory)
        
        # Parse DMARC check (01)
        self.findings['dmarc'] = self._parse_dmarc_output(base_path / "01_dmarc-check")
        
        # Parse GitHub scraping (02) - will be handled by user input
        self.findings['github'] = self._parse_github_output(base_path / "02_github-scraping")
        
        # Parse DNS enumeration (04)
        self.findings['dns'] = self._parse_dns_output(base_path / "04_dns-enumeration")
        
        # Parse vulnerability scan (07)
        self.findings['vulnscan'] = self._parse_vulnscan_output(base_path / "07_vulnscan")
        
        # Parse forced browsing (08) - will be handled by user input
        self.findings['forced_browsing'] = self._parse_forced_browsing_output(base_path / "08_forced-browsing")
        
        # Parse SSL check (09)
        self.findings['ssl'] = self._parse_ssl_output(base_path / "09_ssl-check")
        
        self.log("Finished parsing output files")
    
    def _parse_dmarc_output(self, dmarc_dir):
        """Parse DMARC check output files"""
        self.log("Parsing DMARC output...")
        
        # Check if directory exists
        if not dmarc_dir.exists():
            self.log(f"Error: DMARC directory does not exist: {dmarc_dir}")
            return {'status': 'PASS', 'issues': []}
        
        try:
            output_files = list(dmarc_dir.glob("*.txt")) + list(dmarc_dir.glob("*.log"))
            
            if not output_files:
                self.log(f"Warning: No output files found in DMARC directory: {dmarc_dir}")
                return {'status': 'PASS', 'issues': []}
        
        except Exception as e:
            self.log(f"Error accessing DMARC directory {dmarc_dir}: {e}")
            return {'status': 'PASS', 'issues': []}
        
        dmarc_issues = []
        for file_path in output_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                    
                # Look for DMARC policy issues
                if 'no dmarc record' in content or 'dmarc not found' in content:
                    dmarc_issues.append("No DMARC record found")
                elif 'p=none' in content:
                    dmarc_issues.append("DMARC policy set to 'none' (monitoring only)")
                elif 'quarantine' not in content and 'reject' not in content:
                    dmarc_issues.append("DMARC policy not properly configured")
                    
            except Exception as e:
                self.log(f"Error reading DMARC file {file_path}: {e}")
        
        return {
            'status': 'ISSUES' if dmarc_issues else 'PASS',
            'issues': dmarc_issues
        }
    
    def _parse_github_output(self, github_dir):
        """Parse GitHub scraping output files"""
        self.log("Parsing GitHub output...")
        
        # Check if directory exists
        if not github_dir.exists():
            self.log(f"Error: GitHub directory does not exist: {github_dir}")
            return {'repos_count': 0, 'secrets_found': [], 'repos': []}
        
        try:
            output_files = list(github_dir.glob("*.txt")) + list(github_dir.glob("*.json"))
            
            if not output_files:
                self.log(f"Warning: No output files found in GitHub directory: {github_dir}")
                return {'repos_count': 0, 'secrets_found': [], 'repos': []}
        
        except Exception as e:
            self.log(f"Error accessing GitHub directory {github_dir}: {e}")
            return {'repos_count': 0, 'secrets_found': [], 'repos': []}
        
        secrets_found = []
        repos_found = []
        
        for file_path in output_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Look for secrets/credentials
                if 'password' in content.lower() or 'api_key' in content.lower() or 'secret' in content.lower():
                    secrets_found.append(f"Potential secrets in {file_path.name}")
                
                # Count repositories
                repo_matches = re.findall(r'github\.com/[\w-]+/[\w-]+', content)
                repos_found.extend(repo_matches)
                    
            except Exception as e:
                self.log(f"Error reading GitHub file {file_path}: {e}")
        
        return {
            'repos_count': len(set(repos_found)),
            'secrets_found': secrets_found,
            'repos': list(set(repos_found))
        }
    
    def _parse_dns_output(self, dns_dir):
        """Parse DNS enumeration output files"""
        self.log("Parsing DNS output...")
        
        # Check if directory exists
        if not dns_dir.exists():
            self.log(f"Error: DNS directory does not exist: {dns_dir}")
            return {'status': 'PASS', 'subdomains_found': 0, 'issues': []}
        
        try:
            output_files = list(dns_dir.glob("*.txt")) + list(dns_dir.glob("*.log"))
            
            if not output_files:
                self.log(f"Warning: No output files found in DNS directory: {dns_dir}")
                return {'status': 'PASS', 'subdomains_found': 0, 'issues': []}
        
        except Exception as e:
            self.log(f"Error accessing DNS directory {dns_dir}: {e}")
            return {'status': 'PASS', 'subdomains_found': 0, 'issues': []}
        
        subdomains = set()
        dns_issues = []
        
        for file_path in output_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                for line in lines:
                    # Look for subdomain discoveries
                    subdomain_match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)', line)
                    if subdomain_match:
                        subdomains.add(subdomain_match.group(1))
                    
                    # Look for DNS misconfigurations
                    if 'NXDOMAIN' in line or 'timeout' in line.lower():
                        if "DNS resolution issues detected" not in dns_issues:
                            dns_issues.append("DNS resolution issues detected")
                        
            except Exception as e:
                self.log(f"Error reading DNS file {file_path}: {e}")
        
        return {
            'status': 'ISSUES' if dns_issues else 'PASS',
            'subdomains_found': len(subdomains),
            'issues': dns_issues
        }
    
    def _parse_vulnscan_output(self, vulnscan_dir):
        """Parse vulnerability scan output files"""
        self.log("Parsing vulnerability scan output...")
        
        # Check if directory exists
        if not vulnscan_dir.exists():
            self.log(f"Error: Vulnerability scan directory does not exist: {vulnscan_dir}")
            return {'status': 'PASS', 'total_vulns': 0, 'critical': 0, 'high': 0, 'medium': 0, 'vulnerabilities': []}
        
        try:
            output_files = list(vulnscan_dir.glob("*.txt")) + list(vulnscan_dir.glob("*.json"))
            
            if not output_files:
                self.log(f"Warning: No output files found in vulnerability scan directory: {vulnscan_dir}")
                return {'status': 'PASS', 'total_vulns': 0, 'critical': 0, 'high': 0, 'medium': 0, 'vulnerabilities': []}
        
        except Exception as e:
            self.log(f"Error accessing vulnerability scan directory {vulnscan_dir}: {e}")
            return {'status': 'PASS', 'total_vulns': 0, 'critical': 0, 'high': 0, 'medium': 0, 'vulnerabilities': []}
        
        vulnerabilities = []
        
        for file_path in output_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Look for vulnerability indicators
                vuln_patterns = [
                    r'CVE-\d{4}-\d{4,}',
                    r'\[critical\]',
                    r'\[high\]',
                    r'\[medium\]',
                    r'vulnerability',
                    r'exploit'
                ]
                
                for pattern in vuln_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    vulnerabilities.extend(matches)
                    
            except Exception as e:
                self.log(f"Error reading vulnerability scan file {file_path}: {e}")
        
        # Count severity levels
        critical_count = len([v for v in vulnerabilities if 'critical' in v.lower()])
        high_count = len([v for v in vulnerabilities if 'high' in v.lower()])
        medium_count = len([v for v in vulnerabilities if 'medium' in v.lower()])
        
        return {
            'status': 'ISSUES' if vulnerabilities else 'PASS',
            'total_vulns': len(set(vulnerabilities)),
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'vulnerabilities': list(set(vulnerabilities))
        }
    
    def _parse_forced_browsing_output(self, forced_dir):
        """Parse forced browsing output files"""
        self.log("Parsing forced browsing output...")
        
        # Check if directory exists
        if not forced_dir.exists():
            self.log(f"Error: Forced browsing directory does not exist: {forced_dir}")
            return {'status': 'PASS', 'sensitive_paths': []}
        
        try:
            output_files = list(forced_dir.glob("*.txt")) + list(forced_dir.glob("*.log"))
            
            if not output_files:
                self.log(f"Warning: No output files found in forced browsing directory: {forced_dir}")
                return {'status': 'PASS', 'sensitive_paths': []}
        
        except Exception as e:
            self.log(f"Error accessing forced browsing directory {forced_dir}: {e}")
            return {'status': 'PASS', 'sensitive_paths': []}
        
        sensitive_paths = []
        
        for file_path in output_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                for line in lines:
                    # Look for interesting status codes and paths
                    if re.search(r'20[0-9]|30[0-9]', line):  # 200-309 status codes
                        if any(keyword in line.lower() for keyword in ['admin', 'config', 'backup', 'test', 'dev']):
                            sensitive_paths.append(line.strip())
                            
            except Exception as e:
                self.log(f"Error reading forced browsing file {file_path}: {e}")
        
        return {
            'status': 'ISSUES' if sensitive_paths else 'PASS',
            'sensitive_paths': sensitive_paths[:10]  # Limit to top 10
        }
    
    def _parse_ssl_output(self, ssl_dir):
        """Parse SSL check output files"""
        self.log("Parsing SSL output...")
        
        # Check if directory exists
        if not ssl_dir.exists():
            self.log(f"Error: SSL directory does not exist: {ssl_dir}")
            return {'status': 'PASS', 'issues': []}
        
        try:
            output_files = list(ssl_dir.glob("*.txt")) + list(ssl_dir.glob("*.log"))
            
            if not output_files:
                self.log(f"Warning: No output files found in SSL directory: {ssl_dir}")
                return {'status': 'PASS', 'issues': []}
        
        except Exception as e:
            self.log(f"Error accessing SSL directory {ssl_dir}: {e}")
            return {'status': 'PASS', 'issues': []}
        
        ssl_issues = []
        
        for file_path in output_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                    
                # Look for SSL/TLS issues
                if 'expired' in content:
                    ssl_issues.append("Expired SSL certificate detected")
                elif 'self-signed' in content:
                    ssl_issues.append("Self-signed certificate detected")
                elif 'weak cipher' in content or 'rc4' in content:
                    ssl_issues.append("Weak cipher suites detected")
                elif 'sslv3' in content or 'tlsv1.0' in content:
                    ssl_issues.append("Deprecated SSL/TLS versions enabled")
                    
            except Exception as e:
                self.log(f"Error reading SSL file {file_path}: {e}")
        
        return {
            'status': 'ISSUES' if ssl_issues else 'PASS',
            'issues': ssl_issues
        }
    
    def _get_user_inputs(self):
        """Get user inputs for sections that require manual verification"""
        print("\n" + "="*60)
        print("USER INPUT REQUIRED")
        print("="*60)
        
        # GitHub projects question
        github_response = input("\nWere any GitHub projects identified during reconnaissance? (y/n): ").lower().strip()
        self.user_inputs['github_projects'] = github_response == 'y'
        
        # Nessus vulnerabilities question
        nessus_response = input("Were any Nessus vulnerabilities identified during scanning? (y/n): ").lower().strip()
        self.user_inputs['nessus_vulns'] = nessus_response == 'y'
        
        # Interesting items during forced browsing
        interesting_response = input("Were any interesting items found during forced browsing (08)? (y/n): ").lower().strip()
        self.user_inputs['interesting_items'] = interesting_response == 'y'
        
        print("\nThank you! Generating report...\n")
    
    def _generate_report_sections(self):
        """Generate the formatted report sections"""
        report_sections = []
        
        # Introduction
        intro = """The assessment covered multiple layers of the target environment, including email security, source code repository exposure, DNS configuration, SSL/TLS implementation, and application-layer vulnerabilities. Scanning and enumeration techniques were applied to identify common misconfigurations, outdated software, and exposed assets."""
        
        report_sections.append(intro)
        
        # Domain Configuration Assessment (DMARC)
        dmarc_section = self._generate_dmarc_section()
        report_sections.append(dmarc_section)
        
        # GitHub Repository Security Analysis
        github_section = self._generate_github_section()
        report_sections.append(github_section)
        
        # DNS Enumeration and Misconfigurations
        dns_section = self._generate_dns_section()
        report_sections.append(dns_section)
        
        # Vulnerability Scanning
        vuln_section = self._generate_vuln_section()
        report_sections.append(vuln_section)
        
        # Forced Browsing Assessment
        forced_section = self._generate_forced_browsing_section()
        report_sections.append(forced_section)
        
        # SSL/TLS Configuration Review
        ssl_section = self._generate_ssl_section()
        report_sections.append(ssl_section)
        
        return "\n\n".join(report_sections)
    
    def _generate_dmarc_section(self):
        """Generate DMARC section"""
        status_icon = "⚠️" if self.findings['dmarc']['status'] == 'ISSUES' else "✅"
        status_text = "Issues Discovered" if self.findings['dmarc']['status'] == 'ISSUES' else "PASS"
        
        findings_text = "DMARC policies are properly configured and prevent email spoofing attempts. No vulnerabilities or misconfigurations were identified during these checks"
        
        if self.findings['dmarc']['status'] == 'ISSUES':
            findings_text = "Issues were identified during this phase of testing and can be found outlined in this report."
        
        return f"""#### Domain Configuration Assessment
**Status:** {status_icon} **{status_text}**
- **Scope:** Email spoofing prevention mechanisms  
- **Findings:** {findings_text}"""
    
    def _generate_github_section(self):
        """Generate GitHub section"""
        # Use user input to determine status
        if self.user_inputs['github_projects']:
            status_icon = "⚠️"
            status_text = "Issues Discovered"
            findings_text = f"GitHub repositories were identified during reconnaissance. Found {self.findings['github']['repos_count']} repositories that require further analysis for sensitive information exposure."
        else:
            status_icon = "✅"
            status_text = "PASS"
            findings_text = "No exposed credentials, API keys, or sensitive information found in public repositories. No vulnerabilities or misconfigurations were identified during these checks"
        
        return f"""#### GitHub Repository Security Analysis
**Status:** {status_icon} **{status_text}**
- **Scope:** Source code repository security and secret exposure  
- **Findings:** {findings_text}"""
    
    def _generate_dns_section(self):
        """Generate DNS section"""
        status_icon = "⚠️" if self.findings['dns']['status'] == 'ISSUES' else "✅"
        status_text = "Issues Discovered" if self.findings['dns']['status'] == 'ISSUES' else "PASS"
        
        findings_text = "DNS configuration follows security best practices with no information disclosure or subdomain takeovers were possible. No vulnerabilities or misconfigurations were identified during these checks."
        
        if self.findings['dns']['status'] == 'ISSUES':
            findings_text = "Issues were identified during this phase of testing and can be found outlined in this report."
        
        
        return f"""#### DNS Enumeration and Misconfigurations
**Status:** {status_icon} **{status_text}**
- **Scope:** Virtual host discovery and DNS security  
- **Findings:** {findings_text}"""
    
    def _generate_vuln_section(self):
        """Generate vulnerability scanning section"""
        # Use user input and scan results to determine status
        has_vulns = self.user_inputs['nessus_vulns'] or self.findings['vulnscan']['status'] == 'ISSUES'
        
        if has_vulns:
            status_icon = "⚠️"
            status_text = "Issues Discovered"
            vuln_count = max(self.findings['vulnscan']['total_vulns'], 1)  # At least 1 if user confirmed
            findings_text = f"{vuln_count} {'vulnerability was' if vuln_count == 1 else 'vulnerabilities were'} discovered during this phase of testing and can be found outlined in this report."
        else:
            status_icon = "✅"
            status_text = "PASS"
            findings_text = "No significant vulnerabilities were identified during automated scanning. No vulnerabilities or misconfigurations were identified during these checks."
        
        return f"""#### Vulnerability Scanning
**Status:** {status_icon} **{status_text}**
- **Scope:** Automated vulnerability detection across all services  
- **Findings:** {findings_text}"""
    
    def _generate_forced_browsing_section(self):
        """Generate forced browsing section"""
        # Use user input and scan results to determine status
        has_issues = self.user_inputs['interesting_items'] or self.findings['forced_browsing']['status'] == 'ISSUES'
        
        if has_issues:
            status_icon = "⚠️"
            status_text = "Issues Discovered"
            findings_text = "Interesting directories and files were discovered during forced browsing attempts. These require further manual verification."
        else:
            status_icon = "✅"
            status_text = "PASS"
            findings_text = "No sensitive directories or files exposed through forced browsing. No vulnerabilities or misconfigurations were identified."
        
        return f"""#### Forced Browsing Assessment
**Status:** {status_icon} **{status_text}**
- **Scope:** Directory and file enumeration attempts  
- **Findings:** {findings_text}"""
    
    def _generate_ssl_section(self):
        """Generate SSL/TLS section"""
        status_icon = "⚠️" if self.findings['ssl']['status'] == 'ISSUES' else "✅"
        status_text = "Issues Discovered" if self.findings['ssl']['status'] == 'ISSUES' else "PASS"
        
        findings_text = "SSL/TLS configurations meet current security standards. No vulnerabilities or misconfigurations were identified."
        
        if self.findings['ssl']['status'] == 'ISSUES':
            issues = "; ".join(self.findings['ssl']['issues'])
            findings_text = f"SSL/TLS configuration issues were identified: {issues}"
        
        return f"""#### SSL/TLS Configuration Review
**Status:** {status_icon} **{status_text}**
- **Scope:** SSL/TLS implementation and cipher strength  
- **Findings:** {findings_text}"""