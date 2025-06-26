#!/usr/bin/env python3

import argparse
import sys
import os
from lib.processors.vulnscan_processor import VulnScanProcessor
from lib.processors.vulnimport_processor import VulnImportProcessor
from lib.processors.vulnupload_processor import VulnUploadProcessor
from lib.processors.reportcompletion_processor import ReportCompletionProcessor
from lib.processors.ept_processor import EPTProcessor
from lib.processors.m365upload_processor import M365UploadProcessor
from lib.processors.m365completion_processor import M365CompletionProcessor

def main():
    parser = argparse.ArgumentParser(
        description="Reporting Sidekick - A comprehensive reporting tool for security assessments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Report Types:
  vulnScan        Process vulnerability scan results from multiple tools
  eptReport       Generate EPT assessment reports from scan outputs
  M365Review      Process Microsoft 365 security assessment results

Examples:
  reporting_sidekick.py vulnScan reportCreator --nessus /path/to/nessus --nuclei /path/to/nuclei
  reporting_sidekick.py vulnScan importVulns --nessus /path/to/nessus --nuclei /path/to/nuclei
  reporting_sidekick.py vulnScan uploadVulnsToReport --xlsx report.xlsx --project-id abc123
  reporting_sidekick.py vulnScan completeReport --project-id abc123 --sections executive_summary
  reporting_sidekick.py eptReport --directory /path/to/ept-output
  reporting_sidekick.py M365Review uploadVulnsToReport --xlsx report.xlsx --project-id abc123
  reporting_sidekick.py M365Review completeReport --project-id abc123 --sections executive_summary
        """
    )
    
    # Add subparsers for different report types
    subparsers = parser.add_subparsers(dest='report_type', help='Type of report to generate')
    subparsers.required = True
    
    # VulnScan subparser
    vulnscan_parser = subparsers.add_parser(
        'vulnScan', 
        help='Process vulnerability scan results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reporting_sidekick.py vulnScan reportCreator --nessus /path/to/nessus --nuclei /path/to/nuclei
  reporting_sidekick.py vulnScan reportCreator -n ./nessus_scans -u ./nuclei_scans -o report.xlsx -v
  reporting_sidekick.py vulnScan importVulns --nessus /path/to/nessus --nuclei /path/to/nuclei
  reporting_sidekick.py vulnScan uploadVulnsToReport --xlsx report.xlsx --project-id abc123
        """
    )
    
    # Add subparsers for vulnScan actions
    vulnscan_subparsers = vulnscan_parser.add_subparsers(dest='vulnscan_action', help='VulnScan action to perform')
    vulnscan_subparsers.required = True
    
    # reportCreator subparser
    reportcreator_parser = vulnscan_subparsers.add_parser(
        'reportCreator',
        help='Create vulnerability reports from scan results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reporting_sidekick.py vulnScan reportCreator --nessus /path/to/nessus --nuclei /path/to/nuclei
  reporting_sidekick.py vulnScan reportCreator -n ./nessus_scans -u ./nuclei_scans -o report.xlsx -v --debug
        """
    )
    
    reportcreator_parser.add_argument(
        '--nessus', '-n',
        type=str,
        required=True,
        help='Directory containing Nessus scan files (.nessus)'
    )
    
    reportcreator_parser.add_argument(
        '--nuclei', '-u',
        type=str,
        required=True,
        help='Directory containing Nuclei scan files (.json, .txt)'
    )
    
    reportcreator_parser.add_argument(
        '--output', '-o',
        type=str,
        default='vulnerability_report.xlsx',
        help='Output XLSX filename (default: vulnerability_report.xlsx)'
    )
    
    reportcreator_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    reportcreator_parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode (includes additional columns: Source, Source File, CVSS Vector)'
    )
    
    # importVulns subparser
    importvulns_parser = vulnscan_subparsers.add_parser(
        'importVulns',
        help='Check scan results against SysReptor templates and import new ones',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reporting_sidekick.py vulnScan importVulns --nessus /path/to/nessus --nuclei /path/to/nuclei
  reporting_sidekick.py vulnScan importVulns -n ./nessus_scans -u ./nuclei_scans --verbose
        """
    )
    
    importvulns_parser.add_argument(
        '--nessus', '-n',
        type=str,
        required=True,
        help='Directory containing Nessus scan files (.nessus)'
    )
    
    importvulns_parser.add_argument(
        '--nuclei', '-u',
        type=str,
        required=True,
        help='Directory containing Nuclei scan files (.json, .txt)'
    )
    
    importvulns_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    # uploadVulnsToReport subparser
    uploadvulns_parser = vulnscan_subparsers.add_parser(
        'uploadVulnsToReport',
        help='Upload vulnerabilities from XLSX report to SysReptor project',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reporting_sidekick.py vulnScan uploadVulnsToReport --xlsx report.xlsx --project-id dda636c2-17fb-43e3-87a7-e45cccb8abbd
  reporting_sidekick.py vulnScan uploadVulnsToReport -x report.xlsx -p abc123 --mode grouped --verbose
  reporting_sidekick.py vulnScan uploadVulnsToReport -x report.xlsx -p abc123 --mode individual --preview
        """
    )
    
    uploadvulns_parser.add_argument(
        '--xlsx', '-x',
        type=str,
        required=True,
        help='Path to XLSX vulnerability report file'
    )
    
    uploadvulns_parser.add_argument(
        '--project-id', '-p',
        type=str,
        required=True,
        help='SysReptor project ID to upload vulnerabilities to'
    )
    
    uploadvulns_parser.add_argument(
        '--mode', '-m',
        type=str,
        choices=['grouped', 'individual'],
        default='grouped',
        help='Upload mode: "grouped" (group by title) or "individual" (one per instance) [default: grouped]'
    )
    
    uploadvulns_parser.add_argument(
        '--preview',
        action='store_true',
        help='Show preview of what would be uploaded without actually uploading'
    )
    
    uploadvulns_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    # completeReport subparser
    completereport_parser = vulnscan_subparsers.add_parser(
        'completeReport',
        help='Complete report sections using ChatGPT automation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reporting_sidekick.py vulnScan completeReport --project-id 435021b8-bba0-4dda-a221-ff1d56b72931
  reporting_sidekick.py vulnScan completeReport -p abc123 --sections executive_summary identified_risks
  reporting_sidekick.py vulnScan completeReport -p abc123 --sections compliance_impact --verbose
  reporting_sidekick.py vulnScan completeReport -p abc123 --preview
        """
    )
    
    completereport_parser.add_argument(
        '--project-id', '-p',
        type=str,
        required=True,
        help='SysReptor project ID to complete report sections for'
    )
    
    completereport_parser.add_argument(
        '--sections', '-s',
        nargs='*',
        choices=['executive_summary', 'identified_risks', 'compliance_impact'],
        help='Specific sections to complete. If not specified, completes all sections'
    )
    
    completereport_parser.add_argument(
        '--preview',
        action='store_true',
        help='Show preview of what would be completed without actually completing'
    )
    
    completereport_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    # EPT Report subparser
    ept_parser = subparsers.add_parser(
        'eptReport',
        help='Generate EPT assessment reports from scan outputs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reporting_sidekick.py eptReport --directory /path/to/ept-output
  reporting_sidekick.py eptReport -d ./client-assessment --verbose
        """
    )
    
    ept_parser.add_argument(
        '--directory', '-d',
        type=str,
        required=True,
        help='Directory containing EPT scan output files (should follow ept-template structure)'
    )
    
    ept_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    # M365Review subparser
    m365_parser = subparsers.add_parser(
        'M365Review',
        help='Process Microsoft 365 security assessment results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reporting_sidekick.py M365Review uploadVulnsToReport --xlsx report.xlsx --project-id abc123
  reporting_sidekick.py M365Review uploadVulnsToReport -x report.xlsx -p abc123 --mode grouped --verbose
  reporting_sidekick.py M365Review completeReport --project-id abc123 --sections executive_summary
        """
    )
    
    # Add subparsers for M365Review actions
    m365_subparsers = m365_parser.add_subparsers(dest='m365_action', help='M365Review action to perform')
    m365_subparsers.required = True

    # uploadVulnsToReport subparser for M365Review
    m365_uploadvulns_parser = m365_subparsers.add_parser(
        'uploadVulnsToReport',
        help='Upload M365 vulnerabilities from XLSX report to SysReptor project',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reporting_sidekick.py M365Review uploadVulnsToReport --xlsx report.xlsx --project-id dda636c2-17fb-43e3-87a7-e45cccb8abbd
  reporting_sidekick.py M365Review uploadVulnsToReport -x report.xlsx -p abc123 --mode grouped --verbose
  reporting_sidekick.py M365Review uploadVulnsToReport -x report.xlsx -p abc123 --mode individual --preview
        """
    )
    
    m365_uploadvulns_parser.add_argument(
        '--xlsx', '-x',
        type=str,
        required=True,
        help='Path to XLSX M365 vulnerability report file'
    )
    
    m365_uploadvulns_parser.add_argument(
        '--project-id', '-p',
        type=str,
        required=True,
        help='SysReptor project ID to upload M365 vulnerabilities to'
    )
    
    m365_uploadvulns_parser.add_argument(
        '--mode', '-m',
        type=str,
        choices=['grouped', 'individual'],
        default='grouped',
        help='Upload mode: "grouped" (group by title) or "individual" (one per instance) [default: grouped]'
    )
    
    m365_uploadvulns_parser.add_argument(
        '--preview',
        action='store_true',
        help='Show preview of what would be uploaded without actually uploading'
    )
    
    m365_uploadvulns_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    m365_uploadvulns_parser.add_argument(
        '--filter-severity',
        nargs='*',
        choices=['critical', 'high', 'medium', 'low', 'info'],
        help='Filter by severity levels (e.g., --filter-severity high critical)'
    )
    
    m365_uploadvulns_parser.add_argument(
        '--filter-category',
        nargs='*',
        help='Filter by insight categories'
    )
    
    m365_uploadvulns_parser.add_argument(
        '--filter-validation',
        nargs='*',
        choices=['TP', 'FP'],
        default=['TP'],
        help='Filter by validation status (default: TP only)'
    )
    
    m365_uploadvulns_parser.add_argument(
        '--filter-status',
        nargs='*',
        choices=['open', 'closed'],
        default=['open'],
        help='Filter by insight status (default: open only)'
    )

    # completeReport subparser for M365Review
    m365_completereport_parser = m365_subparsers.add_parser(
        'completeReport',
        help='Complete M365 report sections using ChatGPT automation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reporting_sidekick.py M365Review completeReport --project-id 435021b8-bba0-4dda-a221-ff1d56b72931
  reporting_sidekick.py M365Review completeReport -p abc123 --sections executive_summary identified_risks
  reporting_sidekick.py M365Review completeReport -p abc123 --sections compliance_impact --verbose
  reporting_sidekick.py M365Review completeReport -p abc123 --preview
        """
    )
    
    m365_completereport_parser.add_argument(
        '--project-id', '-p',
        type=str,
        required=True,
        help='SysReptor project ID to complete M365 report sections for'
    )
    
    m365_completereport_parser.add_argument(
        '--sections', '-s',
        nargs='*',
        choices=['executive_summary', 'identified_risks', 'compliance_impact', 'compliance_impact_analysis', 'risk_register'],
        help='Specific sections to complete. If not specified, completes all sections'
    )
    
    m365_completereport_parser.add_argument(
        '--preview',
        action='store_true',
        help='Show preview of what would be completed without actually completing'
    )
    
    m365_completereport_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    try:
        if args.report_type == 'vulnScan':
            if args.vulnscan_action == 'reportCreator':
                processor = VulnScanProcessor(verbose=args.verbose)
                processor.process_scans(
                    nessus_dir=args.nessus,
                    nuclei_dir=args.nuclei,
                    output_file=args.output,
                    debug_mode=args.debug
                )
            elif args.vulnscan_action == 'importVulns':
                processor = VulnImportProcessor(verbose=args.verbose)
                processor.check_against_sysreptor(
                    nessus_dir=args.nessus,
                    nuclei_dir=args.nuclei
                )
            elif args.vulnscan_action == 'uploadVulnsToReport':
                processor = VulnUploadProcessor(verbose=args.verbose)
                
                if args.preview:
                    # Show preview only
                    preview = processor.get_upload_preview(args.xlsx, args.mode)
                    if 'error' in preview:
                        print(f"Error: {preview['error']}")
                        sys.exit(1)
                    
                    print(f"=== Upload Preview ===")
                    print(f"XLSX file: {args.xlsx}")
                    print(f"Upload mode: {preview['upload_mode']}")
                    print(f"Total vulnerabilities in XLSX: {preview['total_vulnerabilities_in_xlsx']}")
                    print(f"Vulnerabilities to upload: {preview['vulnerabilities_to_upload']}")
                    print(f"Risk distribution: {preview['risk_distribution']}")
                    print(f"\nSample vulnerabilities:")
                    for vuln in preview['sample_vulnerabilities']:
                        print(f"  - {vuln['upload_title']} [{vuln['risk']}] - CVSS: {vuln['cvss']}")
                else:
                    # Perform actual upload
                    processor.upload_vulnerabilities_to_project(
                        xlsx_file_path=args.xlsx,
                        project_id=args.project_id,
                        upload_mode=args.mode
                    )
            elif args.vulnscan_action == 'completeReport':
                processor = ReportCompletionProcessor(verbose=args.verbose)
                
                if args.preview:
                    # Show preview only
                    preview = processor.preview_completion(args.project_id, args.sections)
                    if 'error' in preview:
                        print(f"Error: {preview['error']}")
                        sys.exit(1)
                    
                    print(f"=== Report Completion Preview ===")
                    print(f"Project: {preview['project_name']}")
                    print(f"Total findings: {preview['total_findings']}")
                    print(f"Sections to complete: {', '.join([s.replace('_', ' ').title() for s in preview['sections_to_complete']])}")
                    print(f"Risk distribution: {preview['risk_distribution']}")
                    if preview.get('frameworks'):
                        print(f"Compliance frameworks: {', '.join(preview['frameworks'])}")
                else:
                    # Perform actual completion
                    completed, failed = processor.complete_report_sections(
                        project_id=args.project_id,
                        sections=args.sections
                    )
                    
                    if completed:
                        print(f"\n🎉 Successfully completed {len(completed)} report sections!")
            else:
                print(f"Error: Unknown vulnScan action '{args.vulnscan_action}'")
                sys.exit(1)
        elif args.report_type == 'eptReport':
            processor = EPTProcessor(verbose=args.verbose)
            processor.generate_ept_report(args.directory)
        elif args.report_type == 'M365Review':
            if args.m365_action == 'uploadVulnsToReport':
                processor = M365UploadProcessor(verbose=args.verbose)
                
                # Build filters from command line arguments
                filters = {}
                if args.filter_severity:
                    filters['severity'] = args.filter_severity
                if args.filter_category:
                    filters['category'] = args.filter_category
                if args.filter_validation:
                    filters['validation'] = args.filter_validation
                if args.filter_status:
                    filters['status'] = args.filter_status
                
                if args.preview:
                    # Show preview only
                    preview = processor.get_upload_preview(args.xlsx, args.mode, filters)
                    if 'error' in preview:
                        print(f"Error: {preview['error']}")
                        sys.exit(1)
                    
                    print(f"=== M365 Upload Preview ===")
                    print(f"Excel file: {args.xlsx}")
                    print(f"Upload mode: {preview['upload_mode']}")
                    print(f"Total M365 vulnerabilities in Excel: {preview['total_vulnerabilities_in_excel']}")
                    print(f"Vulnerabilities to upload: {preview['vulnerabilities_to_upload']}")
                    print(f"Severity distribution: {preview['severity_distribution']}")
                    print(f"Category distribution: {preview['category_distribution']}")
                    if preview['filters_applied']:
                        print(f"Filters applied: {preview['filters_applied']}")
                    print(f"\nSample vulnerabilities:")
                    for vuln in preview['sample_vulnerabilities']:
                        print(f"  - {vuln['upload_title']} [{vuln['severity']}] - Category: {vuln['category']} - Instances: {vuln['instance_count']}")
                else:
                    # Perform actual upload
                    processor.upload_vulnerabilities_to_project(
                        xlsx_file_path=args.xlsx,
                        project_id=args.project_id,
                        upload_mode=args.mode,
                        filters=filters
                    )
            elif args.m365_action == 'completeReport':
                processor = M365CompletionProcessor(verbose=args.verbose)
                
                if args.preview:
                    # Show preview only
                    preview = processor.preview_completion(args.project_id, args.sections)
                    if 'error' in preview:
                        print(f"Error: {preview['error']}")
                        sys.exit(1)
                    
                    print(f"=== M365 Report Completion Preview ===")
                    print(f"Project: {preview['project_name']}")
                    print(f"Project Type: {preview['project_type']}")
                    print(f"Total M365 findings: {preview['total_findings']}")
                    print(f"Sections to complete: {', '.join([s.replace('_', ' ').title() for s in preview['sections_to_complete']])}")
                    print(f"Severity distribution: {preview['severity_distribution']}")
                    print(f"Category distribution: {preview['category_distribution']}")
                    if preview.get('frameworks'):
                        print(f"Compliance frameworks: {', '.join(preview['frameworks'])}")
                else:
                    # Perform actual completion
                    completed, failed = processor.complete_report_sections(
                        project_id=args.project_id,
                        sections=args.sections
                    )
                    
                    if completed:
                        print(f"\n🎉 Successfully completed {len(completed)} M365 report sections!")
            else:
                print(f"Error: Unknown M365Review action '{args.m365_action}'")
                sys.exit(1)
        else:
            print(f"Error: Unknown report type '{args.report_type}'")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {str(e)}")
        if hasattr(args, 'verbose') and args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()