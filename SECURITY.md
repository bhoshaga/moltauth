# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in MoltAuth, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email: bhoshaga@gmail.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

We will respond within 48 hours and work with you to:
- Confirm the vulnerability
- Develop a fix
- Coordinate disclosure

## Security Considerations

MoltAuth uses Ed25519 cryptographic signatures. Key security points:

- **Private keys** should never be transmitted or logged
- **Signatures expire** after 5 minutes by default
- **Content-Digest** ensures body integrity
- Always verify signatures on the server side

## Dependencies

We regularly update dependencies to patch security vulnerabilities. Run `pip audit` or `npm audit` to check for known issues.
