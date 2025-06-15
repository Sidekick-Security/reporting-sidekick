# Reporting Sidekick

A comprehensive, modular reporting tool for security assessments and penetration testing engagements. The tool supports multiple report types and can be easily extended for different security testing scenarios.

## Features

- **Modular Architecture**: Extensible design for multiple report types
- **Vulnerability Scan Processing**: Combines Nessus and Nuclei scan results
- **Professional Reporting**: Generates formatted XLSX reports with color coding and summary statistics
- **Risk-based Sorting**: Automatically sorts findings by risk level (Critical → High → Medium → Low)
- **Intelligent Filtering**: Excludes informational findings to focus on actionable vulnerabilities
- **Batch Processing**: Processes entire directories of scan files

## Installation

### Prerequisites

- Python 3.6 or higher
- Required Python packages:

```bash
pip install pandas openpyxl
```

### Setup

1. Clone or download this repository
2. Ensure all dependencies are installed
3. Make the script executable (optional):

```bash
chmod +x reporting_sidekick.py
```

## Usage

### Typical Vulnerability Assessment Workflow

For vulnerability scans, follow this sequence of commands for complete assessment and reporting:

1. **Import Vulnerabilities** - Check scan results against existing SysReptor templates and import new ones
2. **Upload Vulnerabilities to Report** - Upload consolidated findings from XLSX to SysReptor project  
3. **Complete Report** - Use AI automation to generate executive summary and analysis sections

### Basic Syntax

```bash
python reporting_sidekick.py <report_type> <action> <options>
```

### Available Report Types

#### vulnScan - Vulnerability Scan Processing

##### 1. importVulns - Import New Vulnerability Templates

Compares scan results against existing SysReptor vulnerability templates and allows importing new findings as templates.

**Purpose:** Identify which vulnerabilities from your scans are already documented in SysReptor and which are new findings that should be added as reusable templates.

**Syntax:**
```bash
python reporting_sidekick.py vulnScan importVulns \
  --nessus /path/to/nessus/directory \
  --nuclei /path/to/nuclei/directory \
  --verbose
```

**Options:**
- `--nessus` or `-n`: Directory containing Nessus (.nessus) files
- `--nuclei` or `-u`: Directory containing Nuclei (.json, .txt) files  
- `--verbose` or `-v`: Enable detailed output

**Example:**
```bash
python reporting_sidekick.py vulnScan importVulns \
  --nessus /mnt/c/Users/user/scans/nessus \
  --nuclei /mnt/c/Users/user/scans/nuclei \
  --verbose
```

##### 2. uploadVulnsToReport - Upload Vulnerabilities to SysReptor Project

Uploads vulnerability findings from a generated XLSX report directly into a specific SysReptor project as findings.

**Purpose:** Take the consolidated vulnerability data from your XLSX report and populate it into your SysReptor project for professional report generation.

**Syntax:**
```bash
python reporting_sidekick.py vulnScan uploadVulnsToReport \
  --xlsx /path/to/report.xlsx \
  --project-id PROJECT_ID \
  --mode [grouped|individual] \
  --preview \
  --verbose
```

**Options:**
- `--xlsx` or `-x`: Path to XLSX vulnerability report file
- `--project-id` or `-p`: SysReptor project ID to upload vulnerabilities to
- `--mode` or `-m`: Upload mode - "grouped" (group by title) or "individual" (one per instance) [default: grouped]
- `--preview`: Show preview of what would be uploaded without actually uploading
- `--verbose` or `-v`: Enable detailed output

**Example:**
```bash
python reporting_sidekick.py vulnScan uploadVulnsToReport \
  --xlsx vulnerability_report.xlsx \
  --project-id 6c08a693-426b-4082-b369-8af1658a5515 \
  --mode grouped \
  --verbose
```

##### 3. completeReport - AI-Powered Report Completion

Uses ChatGPT automation to generate executive summary, risk analysis, and compliance impact sections based on the vulnerabilities in your SysReptor project.

**Purpose:** Automatically generate professional narrative sections of your penetration testing report including executive summary, identified risks analysis, and compliance impact assessment.

**Syntax:**
```bash
python reporting_sidekick.py vulnScan completeReport \
  --project-id PROJECT_ID \
  --sections [executive_summary] [identified_risks] [compliance_impact] \
  --preview \
  --verbose
```

**Options:**
- `--project-id` or `-p`: SysReptor project ID to complete report sections for
- `--sections` or `-s`: Specific sections to complete (if not specified, completes all sections)
  - `executive_summary`: High-level summary for executives and stakeholders
  - `identified_risks`: Technical analysis of security risks identified
  - `compliance_impact`: Impact on regulatory compliance requirements
- `--preview`: Show preview of what would be completed without actually completing
- `--verbose` or `-v`: Enable detailed output

**Example:**
```bash
python reporting_sidekick.py vulnScan completeReport \
  --project-id 6c08a693-426b-4082-b369-8af1658a5515 \
  --sections executive_summary identified_risks \
  --verbose
```

##### 4. reportCreator - Generate XLSX Reports from Scans

Combines and processes vulnerability scan results from multiple tools to create formatted XLSX reports.

**Purpose:** Convert raw Nessus and Nuclei scan files into a professional, consolidated XLSX vulnerability report.

**Syntax:**
```bash
python reporting_sidekick.py vulnScan reportCreator \
  --nessus /path/to/nessus/directory \
  --nuclei /path/to/nuclei/directory \
  --output report_name.xlsx \
  --verbose \
  --debug
```

**Options:**
- `--nessus` or `-n`: Directory containing Nessus (.nessus) files
- `--nuclei` or `-u`: Directory containing Nuclei (.json, .txt) files  
- `--output` or `-o`: Output XLSX filename (default: vulnerability_report.xlsx)
- `--verbose` or `-v`: Enable detailed output during processing
- `--debug` or `-d`: Enable debug mode (includes Source, Source File, CVSS Vector columns)

**Example:**
```bash
python reporting_sidekick.py vulnScan reportCreator \
  --nessus /mnt/c/Users/user/scans/nessus \
  --nuclei /mnt/c/Users/user/scans/nuclei \
  --output client_vulnerability_report.xlsx \
  --verbose
```

### Complete Workflow Example

Here's a complete example workflow for processing vulnerability scans:

```bash
# Step 1: Import new vulnerability templates to SysReptor
python reporting_sidekick.py vulnScan importVulns \
  --nessus /mnt/c/Users/user/client/nessus \
  --nuclei /mnt/c/Users/user/client/nuclei \
  --verbose

# Step 2: Generate XLSX report from scans (if needed)
python reporting_sidekick.py vulnScan reportCreator \
  --nessus /mnt/c/Users/user/client/nessus \
  --nuclei /mnt/c/Users/user/client/nuclei \
  --output client_report.xlsx \
  --verbose

# Step 3: Upload vulnerabilities to SysReptor project
python reporting_sidekick.py vulnScan uploadVulnsToReport \
  --xlsx client_report.xlsx \
  --project-id 6c08a693-426b-4082-b369-8af1658a5515 \
  --mode grouped \
  --verbose

# Step 4: Generate AI-powered report sections
python reporting_sidekick.py vulnScan completeReport \
  --project-id 6c08a693-426b-4082-b369-8af1658a5515 \
  --verbose
```

### Examples

**Basic vulnerability scan processing:**
```bash
python reporting_sidekick.py vulnScan --scanProcessor -n ./scans/nessus -u ./scans/nuclei
```

**Custom output file with verbose logging:**
```bash
python reporting_sidekick.py vulnScan --scanProcessor \
  --nessus /home/user/security/nessus_results \
  --nuclei /home/user/security/nuclei_results \
  --output quarterly_assessment.xlsx \
  --verbose
```

**Debug mode with additional columns:**
```bash
python reporting_sidekick.py vulnScan --scanProcessor \
  --nessus ./nessus_scans \
  --nuclei ./nuclei_scans \
  --output debug_report.xlsx \
  --debug --verbose
```

**Processing multiple scan types:**
```bash
# Directory structure:
# scans/
# ├── nessus/
# │   ├── web_scan.nessus
# │   ├── network_scan.nessus
# │   └── database_scan.nessus
# └── nuclei/
#     ├── web_vulns.json
#     ├── cve_scan.txt
#     └── config_issues.txt

python reporting_sidekick.py vulnScan --scanProcessor --nessus ./scans/nessus --nuclei ./scans/nuclei
```

## Debug Mode

The `--debug` flag enables additional columns in the output report for troubleshooting and detailed analysis:

**Additional Debug Columns:**
- **Source**: Which tool identified the finding (Nessus/Nuclei)
- **Source File**: Original scan file name
- **CVSS Vector**: Complete CVSS vector string

**Usage:**
- **Standard Mode**: Clean, concise report with essential vulnerability information
- **Debug Mode**: Extended report with tool attribution and technical details

The debug mode also includes a "Finding Sources" section in the summary sheet showing the distribution of findings by tool.

## Output Format

### Vulnerability Scan Reports

The generated XLSX report contains two worksheets:

#### 1. Vulnerability Report (Main Sheet)
- **Risk-based sorting**: Critical → High → Medium → Low
- **Color coding**: Risk levels highlighted with appropriate colors
- **Comprehensive data**: Includes host information, vulnerability details, remediation guidance
- **Frozen panes**: Easy navigation of large datasets

#### 2. Summary Sheet
- **Risk distribution**: Count and percentage breakdown by risk level
- **Host statistics**: Top hosts by vulnerability count
- **Source breakdown**: Distribution of findings by scan tool

### Report Columns

#### Standard Mode Columns
| Column | Description |
|--------|-------------|
| Risk Level | Vulnerability risk rating (Critical/High/Medium/Low) |
| Host IP | Target host IP address |
| Hostname | Target hostname (if available) |
| Port | Affected port number |
| Protocol | Network protocol (TCP/UDP) |
| Service | Service information and version |
| Vulnerability Title | Descriptive title of the vulnerability |
| Description | Detailed vulnerability description |
| Remediation | Recommended remediation steps |
| CVSS Score | Common Vulnerability Scoring System score |
| CVE References | Related CVE identifiers |
| Vulnerability Type | Category of vulnerability |

#### Additional Debug Mode Columns
| Column | Description |
|--------|-------------|
| Source | Scan tool that identified the finding (Nessus/Nuclei) |
| Source File | Original scan file name |
| CVSS Vector | Complete CVSS vector string |

## Supported File Formats

### Nessus Files
- **Format**: `.nessus` (XML format)
- **Source**: Nessus vulnerability scanner exports
- **Processing**: Extracts vulnerability details, risk ratings, host information, and remediation guidance

### Nuclei Files
- **Formats**: `.json` and `.txt` (JSON format, supports both JSON arrays and JSONL)
- **Source**: Nuclei vulnerability scanner outputs
- **Processing**: Extracts template-based vulnerability findings, severity levels, and target information

## Risk Assessment Logic

### Nessus Risk Mapping
- Utilizes native Nessus risk ratings (Critical/High/Medium/Low/Informational)
- Informational findings are automatically filtered out

### Nuclei Risk Assignment
The tool maps Nuclei severity levels to standardized risk ratings:

- **Critical**: High-impact vulnerabilities requiring immediate attention
- **High**: Significant security issues that should be addressed promptly
- **Medium**: Moderate risk vulnerabilities that need remediation
- **Low**: Minor security concerns or configuration issues
- **Informational**: Filtered out automatically

## Directory Structure

```
vulnScanning-Reporter/
├── reporting_sidekick.py   # Main executable script
├── README.md               # This documentation
├── docs/                   # Additional documentation
├── output/                 # Generated reports
├── venv/                   # Virtual environment (if used)
└── lib/                    # Library modules
    ├── __init__.py
    ├── processors/         # Report processors
    │   ├── __init__.py
    │   └── vulnscan_processor.py
    ├── parsers/            # File parsers
    │   ├── __init__.py
    │   ├── nessus_parser.py
    │   └── nuclei_parser.py
    └── generators/         # Report generators
        ├── __init__.py
        └── xlsx_generator.py
```

## Error Handling

The tool includes comprehensive error handling for:
- Invalid file formats
- Corrupted scan files
- Missing directories
- Permission issues
- Memory constraints with large datasets

Enable verbose mode (`-v`) for detailed error reporting and debugging information.

## Performance Considerations

- **Memory Usage**: Large scan files are processed efficiently using streaming XML parsing
- **Processing Time**: Depends on the number and size of scan files
- **Output Size**: XLSX files can become large with extensive findings; consider filtering by risk level for large datasets

## Troubleshooting

### Common Issues

**Issue**: "Directory not found" error
**Solution**: Verify directory paths exist and are accessible

**Issue**: "No findings to report" 
**Solution**: Check that scan files contain valid data and aren't all informational findings

**Issue**: Permission denied errors
**Solution**: Ensure read permissions on input directories and write permissions on output location

**Issue**: Memory errors with large files
**Solution**: Process files in smaller batches or increase available system memory

### Debugging

Use the `--verbose` flag to enable detailed logging:
```bash
python reporting_sidekick.py vulnScan --scanProcessor -n ./nessus -u ./nuclei -v
```

This will show:
- Files being processed
- Number of findings per file
- Filtering results
- Processing statistics

## Extending the Tool

### Adding New Report Types

1. Create a new processor in `lib/processors/`
2. Add the new report type to `reporting_sidekick.py`
3. Update the argument parser with new options
4. Add documentation

### Adding New Parsers

1. Create a new parser in `lib/parsers/`
2. Implement the required parsing methods
3. Integrate with existing processors
4. Add support for new file formats

### Adding New Output Formats

1. Create a new generator in `lib/generators/`
2. Implement the required generation methods
3. Integrate with existing processors
4. Add command line options for new formats

## Contributing

To extend functionality:

1. **Add new report types**: Create processors in the `lib/processors/` directory
2. **Add new scan format support**: Create parsers in the `lib/parsers/` directory
3. **Modify risk assessment**: Update risk mapping in the respective parser
4. **Enhance reporting**: Modify generators in `lib/generators/` for additional output formats
5. **Improve filtering**: Add custom filtering logic in processors

## Security Considerations

- This tool processes security scan data which may contain sensitive information
- Ensure proper handling and storage of generated reports
- Review scan data before sharing reports externally
- Consider implementing additional data sanitization for specific environments

## License

This tool is provided as-is for security assessment purposes. Please ensure compliance with your organization's security policies when processing and sharing vulnerability data.