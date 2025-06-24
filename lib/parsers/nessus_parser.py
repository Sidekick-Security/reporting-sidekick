#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import os
import glob
from pathlib import Path

class NessusParser:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.risk_mapping = {
            '0': 'Informational',
            '1': 'Low',
            '2': 'Medium', 
            '3': 'High',
            '4': 'Critical'
        }
        
    def parse_directory(self, directory_path):
        findings = []
        nessus_files = glob.glob(os.path.join(directory_path, "*.nessus"))
        
        if self.verbose:
            print(f"Found {len(nessus_files)} .nessus files")
        
        for file_path in nessus_files:
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
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for report in root.findall('.//Report'):
                for host in report.findall('.//ReportHost'):
                    host_name = host.get('name', 'Unknown')
                    host_properties = {}
                    
                    # Extract host properties
                    for tag in host.findall('.//tag'):
                        tag_name = tag.get('name', '')
                        tag_value = tag.text or ''
                        host_properties[tag_name] = tag_value
                    
                    # Extract IP address
                    host_ip = host_properties.get('host-ip', host_name)
                    
                    # Process each vulnerability
                    for item in host.findall('.//ReportItem'):
                        finding = self._parse_report_item(item, host_ip, host_name, file_path)
                        if finding:
                            findings.append(finding)
                            
        except ET.ParseError as e:
            raise Exception(f"XML parsing error in {file_path}: {str(e)}")
        except Exception as e:
            raise Exception(f"Error processing {file_path}: {str(e)}")
            
        return findings
    
    def _parse_report_item(self, item, host_ip, host_name, source_file):
        plugin_id = item.get('pluginID', '')
        plugin_name = item.get('pluginName', '')
        port = item.get('port', '')
        protocol = item.get('protocol', '')
        service_name = item.get('svc_name', '')
        severity = item.get('severity', '0')
        
        # Skip if no plugin name
        if not plugin_name:
            return None
            
        # Get risk level
        risk = self.risk_mapping.get(severity, 'Unknown')
        
        # Extract additional details
        description = ''
        solution = ''
        synopsis = ''
        see_also = ''
        cvss_score = ''
        cvss_vector = ''
        cve_refs = []
        
        for child in item:
            if child.tag == 'description':
                description = child.text or ''
            elif child.tag == 'solution':
                solution = child.text or ''  
            elif child.tag == 'synopsis':
                synopsis = child.text or ''
            elif child.tag == 'see_also':
                see_also = child.text or ''
            elif child.tag == 'cvss_base_score':
                cvss_score = child.text or ''
            elif child.tag == 'cvss_vector':
                cvss_vector = child.text or ''
            elif child.tag == 'cve':
                if child.text:
                    cve_refs.append(child.text)
        
        # Create service string
        service_info = f"{port}/{protocol}"
        if service_name:
            service_info += f" ({service_name})"
            
        finding = {
            'source': 'Nessus',
            'source_file': os.path.basename(source_file),
            'host': host_ip,
            'hostname': host_name if host_name != host_ip else '',
            'port': port,
            'protocol': protocol,
            'service': service_info,
            'risk': risk,
            'title': plugin_name,
            'description': description.strip(),
            'solution': solution.strip(),
            'see_also': see_also.strip(),
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'cve_references': ', '.join(cve_refs),
            'vulnerability_type': 'Configuration/Software Issue'
        }
        
        return finding