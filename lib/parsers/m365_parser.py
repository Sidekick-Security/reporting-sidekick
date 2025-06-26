#!/usr/bin/env python3

import pandas as pd
import os
from collections import defaultdict

class M365Parser:
    def __init__(self, verbose=False):
        self.verbose = verbose
        
        # Define column mapping from M365 Excel to SysReptor fields
        self.column_mapping = {
            'title': 'Insight Label',
            'description': 'Insight Description', 
            'severity': 'Risk Level',
            'affected_components': 'Occurrence Message',
            'solution': 'Remediation',
            'status': 'Insight Status',
            'validation': 'Validated (TP/FP)',
            'category': 'Insight Category',
            'service_type': 'Service Type',
            'first_seen': 'First Seen',
            'last_seen': 'Last Seen',
            'object_type': 'Object Type',
            'meta_label': 'Meta Label'
        }
        
        # Define severity mapping
        self.severity_mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info',
            'informational': 'info'
        }
    
    def parse_m365_excel(self, excel_file_path):
        """
        Parse M365 Excel file and return structured vulnerability data
        
        Args:
            excel_file_path (str): Path to the M365 Excel file
            
        Returns:
            list: List of vulnerability dictionaries
        """
        
        if self.verbose:
            print(f"Parsing M365 Excel file: {excel_file_path}")
        
        if not os.path.exists(excel_file_path):
            raise Exception(f"M365 Excel file '{excel_file_path}' does not exist")
        
        try:
            # Load Excel file
            df = pd.read_excel(excel_file_path)
            
            if self.verbose:
                print(f"Loaded {len(df)} rows, {len(df.columns)} columns")
            
            # Validate required columns exist
            self._validate_columns(df)
            
            # Apply default filters (only include validated findings that shouldn't be removed)
            filtered_df = self._apply_default_filters(df)
            
            if self.verbose:
                print(f"After filtering: {len(filtered_df)} rows remaining")
            
            # Convert to vulnerability format
            vulnerabilities = self._convert_to_vulnerabilities(filtered_df)
            
            if self.verbose:
                print(f"Converted to {len(vulnerabilities)} vulnerability records")
            
            return vulnerabilities
            
        except Exception as e:
            raise Exception(f"Failed to parse M365 Excel file: {str(e)}")
    
    def _validate_columns(self, df):
        """Validate that required columns exist in the Excel file"""
        required_columns = ['Insight Label', 'Occurrence Message', 'Risk Level']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            raise Exception(f"Required columns missing: {missing_columns}")
    
    def _apply_default_filters(self, df):
        """Apply default filters to the dataframe"""
        filtered_df = df.copy()
        
        # Filter out findings marked to be removed from report
        if 'Remove from Report' in df.columns:
            filtered_df = filtered_df[filtered_df['Remove from Report'] != 'Yes']
            if self.verbose:
                removed_count = len(df) - len(filtered_df)
                if removed_count > 0:
                    print(f"Filtered out {removed_count} findings marked 'Remove from Report'")
        
        # Only include validated True Positives
        if 'Validated (TP/FP)' in df.columns:
            before_tp_filter = len(filtered_df)
            filtered_df = filtered_df[filtered_df['Validated (TP/FP)'] == 'TP']
            tp_count = len(filtered_df)
            if self.verbose:
                filtered_count = before_tp_filter - tp_count
                if filtered_count > 0:
                    print(f"Filtered out {filtered_count} non-TP findings")
                print(f"Keeping {tp_count} True Positive findings for upload")
        
        return filtered_df
    
    def _convert_to_vulnerabilities(self, df):
        """Convert DataFrame rows to vulnerability dictionaries"""
        vulnerabilities = []
        
        for _, row in df.iterrows():
            vuln = {}
            
            # Map columns to SysReptor fields
            for sysreptor_field, excel_column in self.column_mapping.items():
                if excel_column in df.columns:
                    value = row[excel_column]
                    # Handle NaN values
                    if pd.isna(value):
                        value = ''
                    elif not isinstance(value, str):
                        value = str(value)
                    vuln[sysreptor_field] = value
                else:
                    vuln[sysreptor_field] = ''
            
            # Normalize severity
            vuln['severity'] = self._normalize_severity(vuln.get('severity', ''))
            
            # Add additional metadata
            vuln['source'] = 'M365 Security Assessment'
            vuln['plugin_id'] = row.get('Discovered Insight ID', '')
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _normalize_severity(self, severity):
        """Normalize severity values to SysReptor format"""
        if not severity:
            return 'medium'
        
        severity_lower = severity.lower()
        return self.severity_mapping.get(severity_lower, 'medium')
    
    def group_vulnerabilities_by_insight_label(self, vulnerabilities):
        """
        Group vulnerabilities by Insight Label and combine affected components
        
        Args:
            vulnerabilities (list): List of vulnerability dictionaries
            
        Returns:
            list: List of grouped vulnerability dictionaries
        """
        
        if self.verbose:
            print(f"Grouping {len(vulnerabilities)} vulnerabilities by Insight Label")
        
        grouped = defaultdict(lambda: {
            'instances': [],
            'first_occurrence': None,
            'last_occurrence': None
        })
        
        # Group by title (Insight Label)
        for vuln in vulnerabilities:
            title = vuln.get('title', 'Unknown Vulnerability')
            
            # Store the base vulnerability info (first occurrence)
            if not grouped[title]['first_occurrence']:
                grouped[title]['first_occurrence'] = vuln.copy()
            
            # Add instance information
            instance = {
                'affected_component': vuln.get('affected_components', ''),
                'meta_label': vuln.get('meta_label', ''),
                'object_type': vuln.get('object_type', ''),
                'first_seen': vuln.get('first_seen', ''),
                'last_seen': vuln.get('last_seen', '')
            }
            grouped[title]['instances'].append(instance)
            
            # Keep track of latest occurrence
            grouped[title]['last_occurrence'] = vuln
        
        # Convert back to list format
        result = []
        for title, group_data in grouped.items():
            base_vuln = group_data['first_occurrence']
            instances = group_data['instances']
            
            # Create combined affected components string
            affected_components = []
            for instance in instances:
                if instance['affected_component']:
                    affected_components.append(instance['affected_component'])
            
            # Update the vulnerability with grouped data
            grouped_vuln = base_vuln.copy()
            grouped_vuln['affected_components_list'] = affected_components
            grouped_vuln['affected_components'] = '\n\n'.join(affected_components[:10])  # Limit to first 10
            grouped_vuln['instance_count'] = len(instances)
            grouped_vuln['instances'] = instances
            
            # Add summary info
            if len(affected_components) > 10:
                grouped_vuln['affected_components'] += f"\n\n... and {len(affected_components) - 10} more instances"
            
            result.append(grouped_vuln)
        
        if self.verbose:
            print(f"Grouped into {len(result)} unique findings")
            for vuln in result[:3]:  # Show first 3 as examples
                print(f"  - {vuln['title']}: {vuln['instance_count']} instances")
        
        return result
    
    def filter_vulnerabilities(self, vulnerabilities, filters=None):
        """
        Apply additional filters to vulnerabilities
        
        Args:
            vulnerabilities (list): List of vulnerability dictionaries
            filters (dict): Filter criteria
            
        Returns:
            list: Filtered vulnerability list
        """
        
        if not filters:
            return vulnerabilities
        
        filtered = []
        
        for vuln in vulnerabilities:
            include = True
            
            # Apply severity filter
            if 'severity' in filters:
                allowed_severities = filters['severity']
                if isinstance(allowed_severities, str):
                    allowed_severities = [allowed_severities]
                if vuln.get('severity') not in allowed_severities:
                    include = False
            
            # Apply status filter
            if 'status' in filters:
                allowed_statuses = filters['status']
                if isinstance(allowed_statuses, str):
                    allowed_statuses = [allowed_statuses]
                if vuln.get('status') not in allowed_statuses:
                    include = False
            
            # Apply validation filter
            if 'validation' in filters:
                allowed_validations = filters['validation']
                if isinstance(allowed_validations, str):
                    allowed_validations = [allowed_validations]
                if vuln.get('validation') not in allowed_validations:
                    include = False
            
            # Apply category filter
            if 'category' in filters:
                allowed_categories = filters['category']
                if isinstance(allowed_categories, str):
                    allowed_categories = [allowed_categories]
                if vuln.get('category') not in allowed_categories:
                    include = False
            
            if include:
                filtered.append(vuln)
        
        if self.verbose:
            print(f"Applied filters: {len(vulnerabilities)} -> {len(filtered)} vulnerabilities")
        
        return filtered