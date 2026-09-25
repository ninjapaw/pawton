# Security Policy

This repository is an independent Ninja Paw cloud-security training demo maintained by Dr Bill
Mcilhargey. It is not a Microsoft product and is not affiliated with, sponsored by, endorsed by,
or supported by Microsoft Corporation.

## Safe Use

- Use only authorized, non-production environments.
- Do not use real customer data, credentials, or business-sensitive information.
- Never commit secrets or place runtime secrets in GitHub variables, logs, or source files.
- Application secrets are provisioned into Azure Key Vault by the deployment scripts; do not
  hand-copy them elsewhere.
- The admin portal's privileged SQL login is a deliberate anti-pattern for this training
  environment. Do not reuse that credential model in production.

## Reporting a Vulnerability

Do not open a public issue for a security vulnerability. Use the repository owner's private
security reporting process. Include the affected component, reproduction steps, impact, and
suggested remediation without including secrets or sensitive data.

For ordinary bugs or documentation issues, use a normal GitHub issue.

## Microsoft Notice

Microsoft trademarks and product names remain the property of Microsoft Corporation.
Contributions from Microsoft employees, if any, are made in an individual capacity and do not
imply Microsoft authorization or sponsorship. This repository is provided publicly at your own
risk.

## License

The source is distributed under the [MIT License](LICENSE). The license does not grant rights to
third-party trademarks or materials.
