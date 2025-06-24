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