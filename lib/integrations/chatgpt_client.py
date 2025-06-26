#!/usr/bin/env python3

from openai import OpenAI
import time
import os
import json
from typing import List, Dict, Optional

class ChatGPTClient:
    def __init__(self, api_key: str, verbose: bool = False):
        self.api_key = api_key
        self.verbose = verbose
        self.client = OpenAI(api_key=api_key)
        
        # Rate limiting settings
        self.max_retries = 3
        self.retry_delay = 2  # seconds
        
    def generate_executive_summary(self, project_details: Dict, vulnerability_details: List[Dict]) -> str:
        """Generate executive summary for the vulnerability scan report using structured template"""
        
        # Count vulnerabilities by severity and get formatted string
        vuln_counts = self._count_vulnerabilities_by_severity(vulnerability_details)
        formatted_vuln_count = vuln_counts["formatted_string"]
        
        # Generate business risks content
        business_risks_content = self.generate_business_risks(project_details, vulnerability_details)
        
        # Construct the detailed prompt with template
        prompt = f"""
        ---Instructions---
        You are a professional report writer for vulnerability scanning engagements. Your task is to generate well-structured, client-focused report sections based on the following information. 
        Ensure the tone is professional and tailored to the client. 
        Use concise language. HTML markdown is supported and should be used where needed in the template. 
        Anything with a [] should be filled in by you using the information in the project details and vulnerability details, do not keep the brackets in the output. 
        Be sure to remove the vulnerability count of any severity that has 0. For example there should be no instances where zero (0) should be written in this section.
        The scope is in a following section and should not be included here. 
        Any numbers should be written as the following "one (1), two (2), etc." 
        Avoid using bold in any sentences that do not already have it, If the sentence has bold, you should keep it in the output. This is going to be directly inserted into a markdown section, so do not include include the word "markdown" in the output.
        If any finding has a medium risk, this should changed in the output to be moderate severity.
        Dates should be written in the following format MM/DD/YYYY
        Words to avoid: comprehensive, robust, significant
        Anything between ---Template--- should be used as the template.
        ---Instructions---

        ---Template---
        [Customer] engaged Sidekick Security to perform a [type of test] vulnerability scan against [summary of scope]. This scan supports [Customer]'s broader strategic cybersecurity initiatives and helps identify weaknesses that may put [Customer]'s mission at stake. This report presents the results of this scan and the potential compliance impacts that Sidekick's findings might have. 

        The goal of this assessment was to [a broad statement about improving the security posture of the organization]. The assessment started on [start date in following format MM/DD/YYYY] and ended on [end date in following format MM/DD/YYYY] and uncovered {formatted_vuln_count}. 

        <figure>
          <chart :width="15" :height="8" :config="{{
            type: 'bar', 
            data: {{
              labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
              datasets: [{{
                data: [
                  {vuln_counts["counts"]["Critical"]},
                  {vuln_counts["counts"]["High"]},
                  {vuln_counts["counts"]["Medium"]},
                  {vuln_counts["counts"]["Low"]},
                  {vuln_counts["counts"]["Informational"]}
                  ],
                  backgroundColor: [
                    cssvar('--color-risk-critical'), 
                    cssvar('--color-risk-high'), 
                    cssvar('--color-risk-medium'), 
                    cssvar('--color-risk-low'), 
                    cssvar('--color-risk-info')
                  ],
              }}]
            }},
            options: {{
              scales: {{y: {{beginAtZero: true, ticks: {{precision: 0}}}}}}, 
              plugins: {{legend: {{display: false}}}},
            }}
          }}" />
          <figcaption>Distribution of identified vulnerabilities</figcaption>
        </figure>

        {business_risks_content}
        ---Template---

        Project Details:
        {project_details}
        
        Vulnerability Details:
        {vulnerability_details}
        
        Vulnerability Counts:
        Critical: {vuln_counts["counts"]["Critical"]}
        High: {vuln_counts["counts"]["High"]}
        Medium/Moderate: {vuln_counts["counts"]["Medium"]}
        Low: {vuln_counts["counts"]["Low"]}
        Formatted Count: {formatted_vuln_count}
        
        Business Risks Content:
        {business_risks_content}
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a professional vulnerability scanning assistant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.6,
                max_tokens=2500
            )
            
            content = response.choices[0].message.content
            
            if self.verbose:
                print(f"  ✓ Generated executive summary ({len(content)} characters)")
            
            return content
            
        except Exception as e:
            raise Exception(f"Failed to generate executive summary: {str(e)}")
    
    def generate_business_risks(self, project_details: Dict, vulnerability_details: List[Dict]) -> str:
        """Generate business risks section for executive summary"""
        
        prompt = f"""
        ---Instructions---
        You are a professional report writer for vulnerability scanning engagements. 
        Your task is to generate well-structured, client-focused report sections based on the following information.
        Ensure the tone is professional and tailored to the client. 
        Use concise language. HTML markdown is supported and should be used where needed in the template. 
        Anything with a [] should be filled in by you using the information in the project details, do not keep the brackets in the output. 
        Avoid using bold in any sentences that do not already have it. If the sentence has bold, you should keep it in the output.
        This is going to be directly inserted into a markdown section, so do not include include the word "markdown" in the output.
        If any finding has a medium risk, this should be changed in the output to be moderate severity.
        Words to avoid: comprehensive, robust, significant
        Anything between ---Template--- should be used as the template.
        ---Instructions---
        ---Template---
        Across the findings summarized above, the following could lead to:
        * [Summarize 4-5 business or compliance risks using the vulnerability details. Use the Compliance_Framework1 and Compliance_Framework2 to help fill in compliance specific information where needed.]

        ---Template---

        Project Details:
        {project_details}
        
        Vulnerability Details:
        {vulnerability_details}
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a professional vulnerability scanning assistant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.6,
                max_tokens=2500
            )
            
            content = response.choices[0].message.content
            
            if self.verbose:
                print(f"  ✓ Generated business risks ({len(content)} characters)")
            
            return content
            
        except Exception as e:
            raise Exception(f"Failed to generate business risks: {str(e)}")
    
    def generate_high_level_recommendations(self, project_details: Dict, vulnerability_details: List[Dict]) -> str:
        """Generate high-level recommendations section for identified risks"""
        
        prompt = f"""
        ---Instructions---
        You are a professional report writer for vulnerability scanning engagements. 
        Your task is to generate well-structured, client-focused report sections based on the following information.
        Ensure the tone is professional and tailored to the client. 
        Use concise language. HTML markdown is supported and should be used where needed in the template. 
        Anything with a [] should be filled in by you using the information in the project details, do not keep the brackets in the output. 
        Avoid using bold in any sentences that do not already have it. If the sentence has bold, you should keep it in the output.
        This is going to be directly inserted into a markdown section, so do not include include the word "markdown" in the output.
        If any finding has a medium risk, this should be changed in the output to be moderate severity.
        Words to avoid: comprehensive, robust, significant
        Anything between ---Template--- should be used as the template.
        ---Instructions---
        ---Template---
        Taking into consideration all of the issues and environment learnings that have been identified throughout this assessment, Sidekick highly recommends to:
        * [Summarize some of the strategic recommendations that client should move forward with. ]

        ---Template---

        Project Details:
        {project_details}
        
        Vulnerability Details:
        {vulnerability_details}
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a professional vulnerability scanning assistant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.6,
                max_tokens=1500
            )
            
            content = response.choices[0].message.content
            
            if self.verbose:
                print(f"  ✓ Generated high-level recommendations ({len(content)} characters)")
            
            return content
            
        except Exception as e:
            raise Exception(f"Failed to generate high-level recommendations: {str(e)}")
    
    def _count_vulnerabilities_by_severity(self, vulnerability_details: List[Dict]) -> Dict:
        """
        Count vulnerabilities by severity level and return formatted string.
        
        :param vulnerability_details: List of dictionaries containing vulnerability information
        :return: Dictionary with counts for each severity level and formatted string
        """
        # Initialize counts
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,  # We'll map this to "Moderate" in the output
            "Low": 0,
            "Informational": 0
        }
        
        # Count vulnerabilities by risk level
        for vuln in vulnerability_details:
            risk_level = vuln.get("risk", vuln.get("Risk Level", "")).title()
            if risk_level in counts:
                counts[risk_level] += 1
        
        # Map number to text representation for the output
        number_to_text = {
            0: "",
            1: "one (1)",
            2: "two (2)",
            3: "three (3)",
            4: "four (4)",
            5: "five (5)",
            6: "six (6)",
            7: "seven (7)",
            8: "eight (8)",
            9: "nine (9)",
            10: "ten (10)"
        }
        
        # For numbers above 10, we'll just use the number format
        for i in range(11, 100):
            number_to_text[i] = f"{i} ({i})"
        
        # Create formatted string parts, skipping zero counts
        formatted_parts = []
        
        if counts["Critical"] > 0:
            formatted_parts.append(f"{number_to_text[counts['Critical']]} critical-risk vulnerabilities")
        
        if counts["High"] > 0:
            formatted_parts.append(f"{number_to_text[counts['High']]} high-risk vulnerabilities")
        
        if counts["Medium"] > 0:
            formatted_parts.append(f"{number_to_text[counts['Medium']]} moderate-risk vulnerabilities")
        
        if counts["Low"] > 0:
            formatted_parts.append(f"{number_to_text[counts['Low']]} low-risk vulnerabilities")
        
        # Combine parts with commas and "and" for the last one
        if len(formatted_parts) > 1:
            formatted_string = ", ".join(formatted_parts[:-1]) + ", and " + formatted_parts[-1]
        elif len(formatted_parts) == 1:
            formatted_string = formatted_parts[0]
        else:
            formatted_string = "no vulnerabilities"  # Fallback if no vulnerabilities
        
        return {
            "counts": counts,
            "formatted_string": formatted_string
        }
    
    def generate_identified_risks(self, findings_data: List[Dict], project_details: Dict) -> str:
        """Generate identified risks section based on findings"""
        
        prompt = f"""
        ---Instructions---
        You are a professional report writer for vulnerability scanning engagements. 
        Your task is to generate well-structured, client-focused report sections based on the following information.
        Ensure the tone is professional and tailored to the client. 
        Use concise language. HTML markdown is supported and should be used where needed in the template. 
        Anything with a [] should be filled in by you using the information in the project details, do not keep the brackets in the output. 
        Avoid using bold in any sentences that do not already have it. If the sentence has bold, you should keep it in the output.
        This is going to be directly inserted into a markdown section, so do not include include the word "markdown" in the output.
        If any finding has a medium risk, this should be changed in the output to be moderate severity.
        Words to avoid: comprehensive, robust, significant
        Anything between ---Template--- should be used as the template.
        ---Instructions---
        ---Template---
        Across the findings summarized above, the following could lead to:
        * [Summarize 4-5 business or compliance risks using the vulnerability details. Use the Compliance_Framework1 and Compliance_Framework2 to help fill in compliance specific information where needed.]

        ---Template---

        Project Details:
        {project_details}
        
        Vulnerability Details:
        {findings_data}
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a professional vulnerability scanning assistant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.6,
                max_tokens=1500
            )
            
            content = response.choices[0].message.content
            
            if self.verbose:
                print(f"  ✓ Generated identified risks ({len(content)} characters)")
            
            return content
            
        except Exception as e:
            raise Exception(f"Failed to generate identified risks: {str(e)}")
    
    def generate_compliance_impact(self, findings_data: List[Dict], compliance_frameworks: List[str]) -> str:
        """Generate compliance impact and analysis section"""
        
        system_prompt = """You are a cybersecurity compliance expert analyzing vulnerability scan results for regulatory impact.

Format your response using SysReptor markdown syntax:
- Use **bold** for framework names and severity levels
- Use bullet points with - for lists  
- Use ## for framework headers
- Use ### for specific requirement subsections
- Include specific control references where applicable"""

        # Extract key vulnerability types
        vuln_types = list(set([f.get('vulnerability_type', 'General') for f in findings_data if f.get('vulnerability_type')]))
        risk_levels = {}
        for level in ['critical', 'high', 'medium', 'low']:
            risk_levels[level] = len([f for f in findings_data if f.get('risk', '').lower() == level])

        frameworks_text = ", ".join(compliance_frameworks) if compliance_frameworks else "Common frameworks (SOC 2, ISO 27001, PCI DSS, HIPAA)"

        user_prompt = f"""Based on the following penetration test results, analyze the compliance impact:

**Vulnerability Types Found:**
{chr(10).join([f"- {vtype}" for vtype in vuln_types[:10]])}

**Risk Distribution:**
- Critical: {risk_levels.get('critical', 0)}
- High: {risk_levels.get('high', 0)} 
- Medium: {risk_levels.get('medium', 0)}
- Low: {risk_levels.get('low', 0)}

**Compliance Frameworks to Consider:**
{frameworks_text}

Create a comprehensive compliance impact analysis including:

## Regulatory Framework Analysis
Map the identified vulnerabilities to specific compliance requirements and controls

## Control Gaps and Deficiencies  
Identify where current security controls fall short of compliance standards

## Remediation Timeline for Compliance
Provide timeline recommendations to meet compliance requirements

## Risk to Compliance Posture
Assess how the findings affect overall compliance standing and certification status

## Recommended Actions
Specific steps to address compliance gaps and maintain regulatory standing

Focus on actionable compliance guidance that security and compliance teams can implement."""

        return self._make_chat_request(system_prompt, user_prompt, "compliance impact")
    
    def get_compliance_mappings(self, vulnerability_details: List[Dict], frameworks: List[str]) -> str:
        """
        Generate compliance control mappings for each vulnerability.
        
        Args:
            vulnerability_details (list): List of vulnerability dictionaries containing title, risk, etc.
            frameworks (list): List of frameworks from project details (e.g., ['SOC 2', 'PCI DSS', 'NIST CSF'])
        
        Returns:
            str: JSON string mapping vulnerabilities to their compliance controls
        """
        # Format vulnerability details for the prompt
        formatted_vulns = []
        for vuln in vulnerability_details:
            formatted_vuln = {
                "title": vuln.get("title", "Unknown"),
                "risk_level": vuln.get("risk", "Unknown"),
                "description": vuln.get("description", ""),
                "cvss_number": vuln.get("cvss_number", 0)
            }
            formatted_vulns.append(formatted_vuln)

        prompt = f"""
        You are a compliance expert for vulnerability scanning. Based on the provided vulnerability details and compliance frameworks,
        generate a dictionary mapping each vulnerability to its relevant compliance controls. 
        Identify two or three controls for each compliance framework
        No framework should ever be blank
        Try to avoid mapping the same control to different vulnerabilities.
        
        Use the following control number formats **only as examples for formatting style** (do NOT use these specific frameworks unless they appear in the 'Available Compliance Frameworks' list):
        - Example Format — SOC 2: "CC6.6", "CC7.2"
        - Example Format — PCI DSS: "6.5.1", "8.1.8"
        - Example Format — NIST CSF: "PR.AC-4", "DE.CM-1"

        🔒 **IMPORTANT**:
        Only use the compliance frameworks explicitly listed under "Available Compliance Frameworks" below. Do NOT introduce any others in your output.

        
        Return ONLY a valid JSON dictionary with the following structure:
        {{
            "Vulnerability Title": {{
                "Framework": ["Control1", "Control2"],
            }}
        }}

        Available Compliance Frameworks:
        {frameworks}
        
        Vulnerability Details:
        {formatted_vulns}
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a compliance expert. Return only valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            content = response.choices[0].message.content
            
            # Clean up ChatGPT formatting artifacts
            content = self._clean_json_response(content)
            
            if self.verbose:
                print(f"  ✓ Generated compliance mappings ({len(content)} characters)")
            
            return content
            
        except Exception as e:
            raise Exception(f"Failed to generate compliance mappings: {str(e)}")
    
    def _clean_json_response(self, content: str) -> str:
        """Clean up ChatGPT formatting artifacts from JSON responses"""
        # Remove common ChatGPT formatting artifacts
        content = content.strip()
        
        # Remove ```json and ``` markers
        if content.startswith('```json'):
            content = content[7:]  # Remove ```json
        elif content.startswith('```'):
            content = content[3:]   # Remove ```
            
        if content.endswith('```'):
            content = content[:-3]  # Remove trailing ```
            
        # Remove any remaining leading/trailing whitespace
        content = content.strip()
        
        return content
    
    def _make_chat_request(self, system_prompt: str, user_prompt: str, section_name: str) -> str:
        """Make a request to ChatGPT with retry logic"""
        
        for attempt in range(self.max_retries):
            try:
                if self.verbose:
                    print(f"  → Generating {section_name}... (attempt {attempt + 1})")
                
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    max_tokens=2000,
                    temperature=0.7
                )
                
                content = response.choices[0].message.content
                
                if self.verbose:
                    print(f"  ✓ Generated {section_name} ({len(content)} characters)")
                
                return content
                
            except Exception as e:
                if "rate" in str(e).lower():
                    if self.verbose:
                        print(f"  → Rate limited, waiting {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                    self.retry_delay *= 2  # Exponential backoff
                else:
                    if self.verbose:
                        print(f"  → Error: {str(e)}")
                    if attempt == self.max_retries - 1:
                        raise Exception(f"Failed to generate {section_name} after {self.max_retries} attempts: {str(e)}")
                    time.sleep(self.retry_delay)
        
        raise Exception(f"Failed to generate {section_name} after {self.max_retries} attempts")
    
    def generate_finding_compliance_implications(self, finding: Dict, frameworks: List[str], compliance_mappings: Dict) -> Dict:
        """
        Generate structured compliance implications for a specific finding.
        
        Args:
            finding (Dict): Single finding with title, risk, description, etc.
            frameworks (List[str]): List of compliance frameworks
            compliance_mappings (Dict): Overall compliance mappings data for context
        
        Returns:
            Dict: Structured compliance implications with control details
        """
        finding_title = finding.get('title', 'Unknown')
        
        # Get the specific mappings for this finding from the overall mappings
        finding_mappings = compliance_mappings.get(finding_title, {})
        
        if not finding_mappings:
            return {"error": "No compliance mappings found for this finding"}
        
        prompt = f"""For the vulnerability '{finding_title}', provide a JSON response with descriptions for each compliance control.
        For each control, provide its official title and a 1-2 sentence description of how it relates to the finding.
        
        Controls to describe:
        {json.dumps(finding_mappings, indent=2)}
        
        Desired JSON format:
        {{
            "framework_name": {{
                "control_number": {{
                    "title": "Official Control Title",
                    "description": "1-2 sentence description of how this control relates to the finding"
                }}
            }}
        }}
        
        Return ONLY valid JSON without any additional text or formatting."""
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a compliance expert for penetration testing."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=5000
            )
            
            raw_response = response.choices[0].message.content.strip()
            
            if not raw_response:
                return {"error": "Empty response from OpenAI API"}
            
            # Clean up ChatGPT formatting artifacts
            raw_response = self._clean_json_response(raw_response)
            
            # Parse JSON response
            implications = json.loads(raw_response)
            
            if self.verbose:
                print(f"      ✓ Generated compliance implications for {finding_title}")
            
            return implications
            
        except Exception as e:
            if self.verbose:
                print(f"      ✗ Failed to generate compliance implications for {finding_title}: {str(e)}")
            return {"error": str(e)}

    def test_connection(self) -> bool:
        """Test the ChatGPT API connection"""
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "user", "content": "Test connection. Respond with 'OK'."}
                ],
                max_tokens=10
            )
            return "ok" in response.choices[0].message.content.lower()
        except Exception as e:
            if self.verbose:
                print(f"Connection test failed: {str(e)}")
            return False

    # M365-specific methods
    def generate_m365_executive_summary(self, project_details: Dict, vulnerability_details: List[Dict]) -> str:
        """Generate executive summary for M365 security assessment report"""
        
        # Count vulnerabilities by severity and get formatted string
        vuln_counts = self._count_m365_vulnerabilities_by_severity(vulnerability_details)
        formatted_vuln_count = vuln_counts["formatted_string"]
        
        # Generate M365 business risks content
        business_risks_content = self.generate_m365_business_risks(project_details, vulnerability_details)
        
        # Construct M365-specific prompt
        prompt = f"""
        ---Instructions---
        You are a professional report writer for Microsoft 365 security assessments. Your task is to generate well-structured, client-focused report sections based on the following information. 
        Ensure the tone is professional and tailored to the client. 
        Use concise language. HTML markdown is supported and should be used where needed in the template. 
        Anything with a [] should be filled in by you using the information in the project details and vulnerability details, do not keep the brackets in the output. 
        Be sure to remove the vulnerability count of any severity that has 0. For example there should be no instances where zero (0) should be written in this section.
        The scope is in a following section and should not be included here. 
        Any numbers should be written as the following "one (1), two (2), etc." 
        Avoid using bold in any sentences that do not already have it, If the sentence has bold, you should keep it in the output. This is going to be directly inserted into a markdown section, so do not include include the word "markdown" in the output.
        If any finding has a medium risk, this should changed in the output to be moderate severity.
        Dates should be written in the following format MM/DD/YYYY
        Words to avoid: comprehensive, robust, significant
        Anything between ---Template--- should be used as the template.
        ---Instructions---

        ---Template---
        [Customer] engaged Sidekick Security to perform a Microsoft 365 security configuration assessment against [summary of scope]. This assessment supports [Customer]'s broader strategic cybersecurity initiatives and helps identify configuration weaknesses that may put [Customer]'s cloud environment and data at risk. This report presents the results of this M365 assessment and the potential compliance impacts that Sidekick's findings might have. 

        The goal of this assessment was to [a broad statement about improving the M365 security posture and configuration of the organization]. The assessment started on [start date in following format MM/DD/YYYY] and ended on [end date in following format MM/DD/YYYY] and uncovered {formatted_vuln_count}. 

        {business_risks_content}
        ---Template---
        
        ---Project Details---
        Project Name: {project_details.get('project_name', 'M365 Security Assessment')}
        Project Type: {project_details.get('project_type', 'M365 Configuration Review')}
        Scope: {project_details.get('scope', 'Microsoft 365 tenant configuration')}
        Timeframe: {project_details.get('timeframe', 'Assessment period')}
        ---Project Details---

        ---M365 Vulnerability Details---
        {self._format_m365_vulnerabilities_for_prompt(vulnerability_details)}
        ---M365 Vulnerability Details---
        """
        
        return self._make_chat_request(
            "You are an expert M365 security consultant writing an executive summary.",
            prompt,
            "M365 Executive Summary"
        )

    def generate_m365_business_risks(self, project_details: Dict, vulnerability_details: List[Dict]) -> str:
        """Generate M365-specific business risks content"""
        
        prompt = f"""
        Based on the M365 security findings provided, generate a business-focused paragraph that explains the potential business impact of these M365 configuration weaknesses. Focus on:
        
        1. Data security risks in the cloud environment
        2. Identity and access management concerns
        3. Collaboration security implications
        4. Compliance and regulatory impact
        5. Business continuity risks
        
        Keep it concise (2-3 sentences) and avoid technical jargon. Focus on business impact rather than technical details.
        
        M365 Findings Summary:
        {self._format_m365_vulnerabilities_for_prompt(vulnerability_details)}
        """
        
        return self._make_chat_request(
            "You are a business risk analyst specializing in M365 security.",
            prompt,
            "M365 Business Risks"
        )

    def generate_m365_identified_risks(self, findings_data: List[Dict], project_details: Dict) -> str:
        """Generate M365 Summary of Business Risks section using the standard template"""
        
        prompt = f"""
        ---Instructions---
        You are a professional report writer for M365 security assessments. 
        Your task is to generate well-structured, client-focused report sections based on the following information.
        Ensure the tone is professional and tailored to the client. 
        Use concise language. HTML markdown is supported and should be used where needed in the template. 
        Anything with a [] should be filled in by you using the information in the project details, do not keep the brackets in the output. 
        Avoid using bold in any sentences that do not already have it. If the sentence has bold, you should keep it in the output.
        This is going to be directly inserted into a markdown section, so do not include include the word "markdown" in the output.
        If any finding has a medium risk, this should be changed in the output to be moderate severity.
        Words to avoid: comprehensive, robust, significant
        Anything between ---Template--- should be used as the template.
        ---Instructions---
        ---Template---
        Across the findings summarized above, the following could lead to:
        * [Summarize 4-5 business or compliance risks using the M365 vulnerability details. Use the compliance frameworks to help fill in compliance specific information where needed. Focus on M365-specific business impacts like cloud data exposure, identity management gaps, collaboration security risks, and regulatory compliance violations.]

        ---Template---

        Project Details:
        {project_details}
        
        M365 Vulnerability Details:
        {self._format_m365_vulnerabilities_for_prompt(findings_data)}
        """
        
        return self._make_chat_request(
            "You are a professional M365 security consultant writing business risk analysis.",
            prompt,
            "M365 Summary of Business Risks"
        )

    def generate_m365_high_level_recommendations(self, project_details: Dict, findings_data: List[Dict]) -> str:
        """Generate M365 high-level recommendations using the standard template"""
        
        prompt = f"""
        ---Instructions---
        You are a professional report writer for M365 security assessments. 
        Your task is to generate well-structured, client-focused report sections based on the following information.
        Ensure the tone is professional and tailored to the client. 
        Use concise language. HTML markdown is supported and should be used where needed in the template. 
        Anything with a [] should be filled in by you using the information in the project details, do not keep the brackets in the output. 
        Avoid using bold in any sentences that do not already have it. If the sentence has bold, you should keep it in the output.
        This is going to be directly inserted into a markdown section, so do not include include the word "markdown" in the output.
        If any finding has a medium risk, this should be changed in the output to be moderate severity.
        Words to avoid: comprehensive, robust, significant
        Anything between ---Template--- should be used as the template.
        ---Instructions---
        ---Template---
        Taking into consideration all of the issues and environment learnings that have been identified throughout this M365 assessment, Sidekick highly recommends to:
        * [Summarize some of the strategic M365 recommendations that client should move forward with. Focus on M365-specific improvements like identity and access management, collaboration security, cloud configuration hardening, and compliance alignment.]

        ---Template---

        Project Details:
        {project_details}
        
        M365 Vulnerability Details:
        {self._format_m365_vulnerabilities_for_prompt(findings_data)}
        """
        
        return self._make_chat_request(
            "You are a professional M365 security consultant providing strategic recommendations.",
            prompt,
            "M365 High-Level Recommendations"
        )

    def get_m365_compliance_mappings(self, vulnerability_details: List[Dict], frameworks: List[str]) -> str:
        """Generate M365 compliance mappings organized by finding name"""
        
        frameworks_str = ", ".join(frameworks)
        
        # Extract finding titles for the prompt
        finding_titles = [vuln.get('title', 'Unknown') for vuln in vulnerability_details]
        
        prompt = f"""
        Based on the M365 security findings provided, generate detailed compliance mappings organized by finding name, showing which compliance controls apply to each specific finding.

        Requirements:
        - Organize by finding name first, then list applicable compliance controls
        - Map each finding to specific control IDs in each framework
        - Focus on M365-specific compliance requirements
        - Use control IDs only (not titles or descriptions)
        - Consider M365 cloud security and configuration requirements
        - Use the exact finding titles provided

        Compliance Frameworks to map: {frameworks_str}

        M365 Finding Titles:
        {', '.join(finding_titles)}

        M365 Finding Details:
        {self._format_m365_vulnerabilities_for_prompt(vulnerability_details)}

        Return as JSON structure organized by finding name:
        {{
            "Finding Title 1": {{
                "SOC 2": ["CC6.1", "CC6.2"],
                "NIST CSF": ["PR.AC-1", "PR.DS-1"],
                "ISO 27001": ["A.9.1.1", "A.9.2.1"]
            }},
            "Finding Title 2": {{
                "SOC 2": ["CC7.1"],
                "NIST CSF": ["DE.CM-1"],
                "ISO 27001": ["A.12.4.1"]
            }}
        }}

        Important: Use the exact finding titles from the list above. Only include control IDs that are genuinely relevant to each specific M365 finding.
        """
        
        return self._make_chat_request(
            "You are an M365 compliance expert mapping security findings to compliance frameworks.",
            prompt,
            "M365 Compliance Mappings"
        )

    def generate_m365_finding_compliance_implications(self, finding: Dict, frameworks: List[str], compliance_mappings: Dict) -> Dict:
        """Generate compliance implications for a specific M365 finding"""
        
        frameworks_str = ", ".join(frameworks)
        
        prompt = f"""
        Based on the specific M365 finding provided and the compliance frameworks, generate detailed compliance implications.

        Requirements:
        - Focus on how this specific M365 configuration issue impacts compliance
        - Map to specific controls in each framework
        - Provide clear, actionable compliance impact descriptions
        - Consider M365 cloud security requirements
        - Return as JSON structure

        Compliance Frameworks: {frameworks_str}

        M365 Finding Details:
        Title: {finding.get('title', 'Unknown')}
        Description: {finding.get('description', 'No description')}
        Severity: {finding.get('severity', 'Unknown')}
        Category: {finding.get('vulnerability_type', 'Unknown')}
        Affected Components: {finding.get('affected_components', [])}

        Return as JSON:
        {{
            "framework_name": {{
                "control_id": {{
                    "title": "Control Title",
                    "description": "How this specific M365 finding impacts this control"
                }}
            }}
        }}
        """
        
        try:
            response = self._make_chat_request(
                "You are an M365 compliance expert analyzing specific finding compliance impacts.",
                prompt,
                "M365 Finding Compliance Implications"
            )
            
            # Clean and parse JSON response
            cleaned_response = self._clean_json_response(response)
            return json.loads(cleaned_response)
            
        except json.JSONDecodeError as e:
            if self.verbose:
                print(f"Failed to parse M365 compliance implications JSON: {str(e)}")
            return {"error": f"Failed to parse compliance implications: {str(e)}"}
        except Exception as e:
            if self.verbose:
                print(f"Error generating M365 compliance implications: {str(e)}")
            return {"error": f"Error generating compliance implications: {str(e)}"}

    def _count_m365_vulnerabilities_by_severity(self, vulnerability_details: List[Dict]) -> Dict:
        """Count M365 vulnerabilities by severity level"""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerability_details:
            severity = vuln.get('severity', 'medium').lower()
            if severity in counts:
                counts[severity] += 1
        
        # Generate formatted string for M365 findings
        formatted_parts = []
        severity_names = {
            'critical': 'critical',
            'high': 'high', 
            'medium': 'moderate',  # M365 uses moderate instead of medium
            'low': 'low',
            'info': 'informational'
        }
        
        for severity, count in counts.items():
            if count > 0:
                severity_name = severity_names[severity]
                if count == 1:
                    formatted_parts.append(f"one (1) {severity_name} severity configuration issue")
                else:
                    count_word = self._number_to_word(count)
                    formatted_parts.append(f"{count_word} ({count}) {severity_name} severity configuration issues")
        
        if len(formatted_parts) == 0:
            formatted_string = "no security configuration issues"
        elif len(formatted_parts) == 1:
            formatted_string = formatted_parts[0]
        elif len(formatted_parts) == 2:
            formatted_string = f"{formatted_parts[0]} and {formatted_parts[1]}"
        else:
            formatted_string = f"{', '.join(formatted_parts[:-1])}, and {formatted_parts[-1]}"
        
        return {
            **counts,
            'total': sum(counts.values()),
            'formatted_string': formatted_string
        }

    def _format_m365_vulnerabilities_for_prompt(self, vulnerability_details: List[Dict]) -> str:
        """Format M365 vulnerabilities for ChatGPT prompts"""
        if not vulnerability_details:
            return "No M365 vulnerabilities found."
        
        formatted_vulns = []
        for vuln in vulnerability_details:
            vuln_text = f"Title: {vuln.get('title', 'Unknown')}\n"
            vuln_text += f"Severity: {vuln.get('severity', 'Unknown')}\n"
            vuln_text += f"Category: {vuln.get('vulnerability_type', 'Unknown')}\n"
            vuln_text += f"Description: {vuln.get('description', 'No description')}\n"
            
            affected = vuln.get('affected_components', [])
            if affected:
                if len(affected) == 1 and "View all instances" in affected[0]:
                    vuln_text += f"Affected Components: Multiple instances (see Excel for details)\n"
                else:
                    vuln_text += f"Affected Components: {', '.join(affected[:5])}\n"
                    if len(affected) > 5:
                        vuln_text += f"  ... and {len(affected) - 5} more components\n"
            
            vuln_text += f"Recommendation: {vuln.get('recommendation', 'No recommendation provided')}\n"
            formatted_vulns.append(vuln_text)
        
        return "\n---\n".join(formatted_vulns)

    def _number_to_word(self, num: int) -> str:
        """Convert number to word for M365 reporting"""
        number_words = {
            1: "one", 2: "two", 3: "three", 4: "four", 5: "five",
            6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten",
            11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen", 15: "fifteen",
            16: "sixteen", 17: "seventeen", 18: "eighteen", 19: "nineteen", 20: "twenty"
        }
        
        if num in number_words:
            return number_words[num]
        elif num < 100:
            tens = num // 10
            ones = num % 10
            tens_words = {2: "twenty", 3: "thirty", 4: "forty", 5: "fifty", 
                         6: "sixty", 7: "seventy", 8: "eighty", 9: "ninety"}
            if ones == 0:
                return tens_words[tens]
            else:
                return f"{tens_words[tens]}-{number_words[ones]}"
        else:
            return str(num)

    def generate_m365_compliance_impact_analysis(self, project_details: Dict, vulnerability_details: List[Dict], frameworks: List[str], compliance_mappings: Dict) -> str:
        """Generate M365 Compliance Impact and Analysis section with table"""
        
        # Generate framework descriptions
        frameworks_section = ""
        for framework in frameworks:
            if framework == "SOC 2":
                desc = "SOC 2 (Service Organization Control 2) is a voluntary compliance standard for service providers storing customer data in the cloud."
            elif framework == "NIST CSF" or framework == "NIST Cybersecurity Framework":
                desc = "The NIST Cybersecurity Framework (CSF) is a voluntary set of guidelines and best practices that helps organizations manage cybersecurity risks."
            elif framework == "CMS ARS":
                desc = "CMS Application Risk and Security (ARS) provides security controls for healthcare systems managing protected health information."
            elif framework == "ISO 27001":
                desc = "ISO 27001 is an international standard that provides requirements for establishing, implementing, maintaining and continually improving an information security management system."
            else:
                desc = f"The {framework} framework provides security guidelines and best practices for organizational risk management."
            
            frameworks_section += f"* <b>{framework}</b>: {desc}<br>\n"
        
        # Generate table headers
        table_headers = """<table>
            <thead>
                <tr>
                    <th>Vulnerability</th>"""
        
        for framework in frameworks:
            table_headers += f"\n                    <th>[{framework}] Control Impacted</th>"
        
        table_headers += "\n                    <th>Potential Compliance Consequence</th>\n                </tr>\n            </thead>"
        
        prompt = f"""
        You are a professional report writer for M365 security assessments. 
        Your task is to generate the Compliance Impact and Analysis section based on the following information.
        Ensure the tone is professional and tailored to the client. 
        Use concise language. HTML markdown is supported and should be used where needed in the template. 
        Anything with a [] should be filled in by you using the information in the project details, do not keep the brackets in the output. 
        Avoid using bold in any sentences that do not already have it. 
        This is going to be directly inserted into a markdown section, so do not include the word "markdown" in the output.
        If any finding has a medium risk, this should be changed in the output to be moderate severity.
        Ensure the output does not contain 'html' or three single ticks (```)
        Be sure to put vulnerabilities in order of risk severity with highest being first.

        ---Template---
        Relevant compliance frameworks:<br>
        {frameworks_section}

        The table below maps each vulnerability to the relevant compliance framework controls, highlighting potential compliance consequences:

        {table_headers}
            <tbody>
                <tr>
                    <td style="vertical-align: top;">[Vulnerability title. Be sure to put these in order of risk severity with highest being first]</td>
                    {chr(10).join([f'<td style="vertical-align: top;">[{framework} controls impacted. These should be gathered from the compliance_mappings. Should be in the following format CC6.6{chr(10)}CC7.2{chr(10)}CC9.2 ]</td>' for framework in frameworks])}
                    <td style="vertical-align: top;">[Extremely short explanation of potential compliance consequence for M365 configuration issues]</td>
                </tr>
            </tbody>
        </table>
        ---Template---

        Project Details:
        {project_details}
        
        M365 Vulnerability Details:
        {self._format_m365_vulnerabilities_for_prompt(vulnerability_details)}

        Compliance Mappings:
        {compliance_mappings}
        """
        
        return self._make_chat_request(
            "You are a professional M365 security consultant generating compliance analysis.",
            prompt,
            "M365 Compliance Impact and Analysis"
        )

    def generate_m365_risk_register(self, project_details: Dict, vulnerability_details: List[Dict]) -> str:
        """Generate M365 Risk Register section grouping findings into business risks"""
        
        prompt = f"""
        You are a professional report writer for M365 security assessments. 
        Your task is to generate the Risk Register section based on the provided M365 configuration findings.
        Ensure the tone is professional and tailored to the client.
        
        IMPORTANT: Do NOT treat each M365 technical finding as a separate risk. Instead, group related M365 configuration issues into business-level risks that executives would understand and care about.
        
        Follow these guidelines for creating M365 business risks:
        1. Group related M365 findings by their potential business impact
        2. For example:
           - Group inactive user accounts and improper group permissions into "Identity and access management risks"
           - Group Teams/collaboration security issues into "Data exposure through collaboration platforms"
           - Group Azure security configuration issues into "Cloud infrastructure security gaps"
           - Group MFA and authentication issues into "Authentication bypass risks"
        3. Each business risk entry should:
           - Have a clear business-focused title (not technical)
           - List the specific M365 findings that contribute to this risk
           - Identify the business areas impacted (compliance, reputation, operations, etc.)
           - Provide an overall risk rating based on the combined severity of contributing findings
           - Offer business-focused mitigation recommendations
        
        Use concise language. HTML markdown is supported and should be used where needed in the template. 
        Anything with a [] should be filled in by you using the information in the project details, do not keep the brackets in the output. 
        Avoid using bold in any sentences that do not already have it. 
        This is going to be directly inserted into a markdown section, so do not include the word "markdown" in the output.
        If any finding has a medium risk, this should be changed in the output to be moderate severity.
        Ensure the output does not contain 'html' or three single ticks (```)

        ---Template---
        <h2 id="Risk-Register" class="in-toc numbered">Risk Register</h2>
        <p>
        This section outlines the key business risks identified during the M365 security assessment, categorized across various risk profiles: Compliance Risk, Operational Risk, Reputational Risk, Financial Risk, and Business Continuity Risk. This approach ensures a holistic understanding of how M365 configuration weaknesses translate to business impacts beyond compliance requirements.
        </p>
        <table>
            <thead>
                <tr>
                    <th>Business Risk</th>
                    <th>Contributing M365 Findings</th>
                    <th>Risk Profile(s)</th>
                    <th>Overall Risk Rating</th>
                    <th>Proposed Mitigation Strategy</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td style="vertical-align: top;">[Business-focused risk description that executives would understand, such as "Identity and access management risks" or "Data exposure through collaboration platforms"]</td>
                    <td style="vertical-align: top;">[List the specific M365 finding titles that contribute to this business risk]</td>
                    <td style="vertical-align: top;">[Relevant risk profiles from: Compliance, Operational, Reputational, Financial, and Business Continuity]</td>
                    <td style="vertical-align: top;">[Overall risk rating based on the combined impact/likelihood of contributing M365 findings]</td>
                    <td style="vertical-align: top;">[Business-focused mitigation strategy that addresses the overall M365 risk, not just technical fixes]</td>
                </tr>
            </tbody>
        </table>
        ---Template---

        Project Details:
        {project_details}
        
        M365 Vulnerability Details:
        {self._format_m365_vulnerabilities_for_prompt(vulnerability_details)}
        """
        
        return self._make_chat_request(
            "You are a professional M365 security consultant generating business risk analysis.",
            prompt,
            "M365 Risk Register"
        )