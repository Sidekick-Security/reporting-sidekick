#!/usr/bin/env python3

import pandas as pd
import os
from pathlib import Path

class XLSXParser:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.risk_mapping = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1,
            'Informational': 0
        }
        
    def parse_xlsx_report(self, xlsx_file_path):
        """Parse vulnerability data from XLSX report"""
        if not os.path.exists(xlsx_file_path):
            raise Exception(f"XLSX file '{xlsx_file_path}' does not exist")
        
        if self.verbose:
            print(f"Parsing XLSX file: {xlsx_file_path}")
        
        try:
            # Read the main vulnerability sheet
            df = pd.read_excel(xlsx_file_path, sheet_name=0)  # First sheet
            
            if self.verbose:
                print(f"Found {len(df)} rows in XLSX")
                print(f"Columns: {list(df.columns)}")
            
            # Standardize column names (handle variations)
            df.columns = df.columns.str.strip()
            column_mapping = self._create_column_mapping(df.columns)
            
            if self.verbose:
                print(f"Column mapping: {column_mapping}")
            
            # Parse vulnerabilities
            vulnerabilities = []
            for index, row in df.iterrows():
                try:
                    vuln = self._parse_vulnerability_row(row, column_mapping)
                    if vuln:
                        vulnerabilities.append(vuln)
                except Exception as e:
                    if self.verbose:
                        print(f"Warning: Error parsing row {index + 1}: {str(e)}")
                    continue
            
            if self.verbose:
                print(f"Successfully parsed {len(vulnerabilities)} vulnerabilities")
            
            return vulnerabilities
            
        except Exception as e:
            raise Exception(f"Error parsing XLSX file: {str(e)}")
    
    def _create_column_mapping(self, columns):
        """Create mapping from XLSX columns to standard field names"""
        mapping = {}
        
        # Define possible column name variations
        field_variations = {
            'risk': ['risk level', 'risk_level', 'risk', 'severity', 'criticality'],
            'host': ['host ip', 'host_ip', 'host', 'ip', 'target'],
            'hostname': ['hostname', 'host_name', 'server'],
            'port': ['port', 'port_number'],
            'protocol': ['protocol', 'proto'],
            'service': ['service', 'service_name'],
            'title': ['vulnerability title', 'vuln title', 'title', 'name', 'vulnerability_name', 'vulnerability name'],
            'description': ['description', 'risk_description', 'details', 'vulnerability_description'],
            'solution': ['remediation', 'solution', 'recommendation', 'fix'],
            'cvss_score': ['cvss score', 'cvss_score', 'cvss', 'score'],
            'cve_references': ['cve references', 'cve_references', 'cve', 'references'],
            'vulnerability_type': ['vulnerability type', 'vulnerability_type', 'type', 'category']
        }
        
        # Create reverse mapping for fuzzy matching
        # First pass: exact matches
        for field, variations in field_variations.items():
            for col in columns:
                col_lower = col.lower().strip()
                for variation in variations:
                    if variation.lower() == col_lower:
                        mapping[field] = col
                        break
                if field in mapping:
                    break
        
        # Second pass: partial matches for fields not yet mapped
        for field, variations in field_variations.items():
            if field in mapping:
                continue  # Skip if already mapped
            for col in columns:
                col_lower = col.lower().strip()
                for variation in variations:
                    if variation.lower() in col_lower:
                        mapping[field] = col
                        break
                if field in mapping:
                    break
        
        return mapping
    
    def _parse_vulnerability_row(self, row, column_mapping):
        """Parse a single vulnerability row from XLSX"""
        # Skip empty rows
        if row.isna().all():
            return None
        
        # Extract basic information
        title = self._get_field_value(row, column_mapping, 'title')
        if not title or pd.isna(title):
            return None  # Skip rows without title
        
        # Build vulnerability object
        vulnerability = {
            'title': str(title).strip(),
            'risk': self._get_field_value(row, column_mapping, 'risk', 'Medium'),
            'host': self._get_field_value(row, column_mapping, 'host', ''),
            'hostname': self._get_field_value(row, column_mapping, 'hostname', ''),
            'port': self._get_field_value(row, column_mapping, 'port', ''),
            'protocol': self._get_field_value(row, column_mapping, 'protocol', 'tcp'),
            'service': self._get_field_value(row, column_mapping, 'service', ''),
            'description': self._get_field_value(row, column_mapping, 'description', ''),
            'solution': self._get_field_value(row, column_mapping, 'solution', ''),
            'cvss_score': self._get_field_value(row, column_mapping, 'cvss_score', 0),
            'cve_references': self._get_field_value(row, column_mapping, 'cve_references', ''),
            'vulnerability_type': self._get_field_value(row, column_mapping, 'vulnerability_type', '')
        }
        
        # Clean and validate data
        vulnerability = self._clean_vulnerability_data(vulnerability)
        
        return vulnerability
    
    def _get_field_value(self, row, column_mapping, field, default=''):
        """Get field value from row using column mapping"""
        if field in column_mapping:
            col_name = column_mapping[field]
            value = row.get(col_name, default)
            return value if not pd.isna(value) else default
        return default
    
    def _clean_vulnerability_data(self, vulnerability):
        """Clean and validate vulnerability data"""
        # Clean strings
        for field in ['title', 'description', 'solution', 'host', 'hostname', 'service']:
            if vulnerability[field] and not pd.isna(vulnerability[field]):
                vulnerability[field] = str(vulnerability[field]).strip()
            else:
                vulnerability[field] = ''
        
        # Validate risk level
        risk = str(vulnerability['risk']).strip().title()
        if risk not in self.risk_mapping:
            vulnerability['risk'] = 'Medium'  # Default fallback
        else:
            vulnerability['risk'] = risk
        
        # Clean numeric fields
        try:
            cvss = float(vulnerability['cvss_score']) if vulnerability['cvss_score'] else 0.0
            vulnerability['cvss_score'] = max(0.0, min(10.0, cvss))  # Clamp to 0-10 range
        except (ValueError, TypeError):
            vulnerability['cvss_score'] = 0.0
        
        # Clean port
        try:
            if vulnerability['port']:
                port = int(str(vulnerability['port']).split('/')[0])  # Handle "80/tcp" format
                vulnerability['port'] = str(port)
            else:
                vulnerability['port'] = ''
        except (ValueError, TypeError):
            vulnerability['port'] = ''
        
        return vulnerability
    
    def group_vulnerabilities_by_title(self, vulnerabilities):
        """Group vulnerabilities by title for bulk upload"""
        grouped = {}
        
        for vuln in vulnerabilities:
            title = vuln['title']
            if title not in grouped:
                grouped[title] = {
                    'vulnerability': vuln,
                    'affected_components': []
                }
            
            # Add affected component
            component = self._build_component_string(vuln)
            if component and component not in grouped[title]['affected_components']:
                grouped[title]['affected_components'].append(component)
        
        return grouped
    
    def _build_component_string(self, vulnerability):
        """Build affected component string from vulnerability data"""
        # Primary identifier
        if vulnerability['hostname']:
            primary = vulnerability['hostname']
        elif vulnerability['host']:
            primary = vulnerability['host']
        else:
            return None
        
        # Add port if available - only hostname:port format
        if vulnerability['port']:
            component = f"{primary}:{vulnerability['port']}"
        else:
            component = primary
        
        return component
    
    def get_statistics(self, xlsx_file_path):
        """Get statistics about the XLSX file"""
        try:
            vulnerabilities = self.parse_xlsx_report(xlsx_file_path)
            
            stats = {
                'total_vulnerabilities': len(vulnerabilities),
                'risk_distribution': {},
                'unique_titles': len(set(v['title'] for v in vulnerabilities)),
                'affected_hosts': len(set(v['host'] for v in vulnerabilities if v['host']))
            }
            
            # Risk distribution
            for vuln in vulnerabilities:
                risk = vuln['risk']
                stats['risk_distribution'][risk] = stats['risk_distribution'].get(risk, 0) + 1
            
            return stats
            
        except Exception as e:
            return {'error': str(e)}