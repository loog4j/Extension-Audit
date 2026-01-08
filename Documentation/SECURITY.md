# Security Policy

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability in this project, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues via one of these methods:

1. **GitHub Security Advisories** (Recommended)
   - Navigate to the "Security" tab in this repository
   - Click "Report a vulnerability"
   - Provide detailed information about the vulnerability

2. **Email** (Alternative)
   - Email: [Your security contact email - update this]
   - Subject line: "SECURITY: Browser Extension Audit Vulnerability"
   - Include detailed information about the vulnerability

### What to Include

Please include the following information:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** of the vulnerability
- **Suggested fix** (if you have one)
- **Your contact information** for follow-up

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Varies based on severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium: 30-60 days
  - Low: 60-90 days

### Disclosure Policy

- We will work with you to understand and address the vulnerability
- We will keep you informed of our progress
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- Please allow us reasonable time to address the issue before public disclosure

## Security Best Practices

When deploying this tool in your environment:

### Script Integrity
- Verify script hash before deployment
- Use code signing certificates in production
- Store scripts in access-controlled locations

### Malicious Extension List
- Host the list internally or use trusted sources only
- Use HTTPS URLs when downloading lists
- Validate list contents before deployment
- Review changes to the list regularly

### Event Log Security
- Restrict access to Event Logs containing extension data
- Ensure SIEM systems are properly secured
- Implement appropriate data retention policies

### Deployment Security
- Use least-privilege accounts for scheduled tasks
- Secure GPO configurations
- Protect credentials and API keys
- Audit script execution regularly

### Network Security
- If downloading malicious lists, validate TLS certificates
- Consider proxy requirements in corporate environments
- Implement egress filtering if needed

## Known Security Considerations

### Privacy
This tool logs:
- Extension IDs (public identifiers)
- Extension names (public metadata)
- Windows usernames
- Browser types

This tool does NOT log:
- Browsing history
- Passwords or credentials
- Cookies or session data
- Personal user data

Ensure compliance with:
- Company privacy policies
- Employee monitoring agreements
- Regional privacy regulations (GDPR, CCPA, etc.)

### False Positives
- The malicious extension list may contain false positives
- Review and validate the list before deployment
- Implement a process for handling false positive reports

### Detection Evasion
- Attackers aware of this tool may attempt to evade detection
- This tool is one layer of defense - use defense-in-depth approach
- Consider complementary controls (browser policies, application whitelisting, etc.)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

## Security Updates

Security updates will be released as needed and announced via:
- GitHub Security Advisories
- Repository releases page
- README changelog

Subscribe to repository notifications to stay informed.

## Bug Bounty Program

We currently do not have a bug bounty program. However, we greatly appreciate responsible disclosure and will publicly credit researchers who help improve the security of this tool.

## Questions?

For non-security questions, please open a regular GitHub issue or discussion.

Thank you for helping keep this project secure! 🔒
