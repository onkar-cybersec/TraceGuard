import { RuleMetadata } from './types';

export const RULE_DEFINITIONS: Record<string, RuleMetadata> = {
  TG001: {
    id: 'TG001',
    name: 'Authentication Failure Burst',
    category: 'Credential Attack',
    severity: 'medium',
    threshold_summary: '5+ failed authentication events for the same Source IP and User within a rolling 5-minute window (300s).',
    rationale:
      'High concentrations of failed authentication requests from a single client for an identity typically signify automated password guessing, dictionary attacks, or credential spraying.',
    legitimate_causes:
      'A misconfigured client application, expired stored credentials in a script/CI pipeline, VPN reconnection loops, or a user who forgot their newly updated corporate password.',
    investigation_steps: [
      'Correlate with VPN and single-sign-on (SSO) gateway telemetry for anomalous user agents or geolocations.',
      'Check if the source IP belongs to known company infrastructure, a cloud provider, or a residential proxy / Tor exit node.',
      'Contact the affected user to determine if they recently changed their credentials on multiple devices.',
      'Review target services to confirm whether account lockout or CAPTCHA policies were enforced.',
    ],
  },
  TG002: {
    id: 'TG002',
    name: 'Authentication Success After Failure Burst',
    category: 'Account Compromise',
    severity: 'critical',
    threshold_summary: 'Successful login following 5+ failures for the same Source IP and User within the preceding 10 minutes (600s).',
    rationale:
      'A successful login immediately succeeding a burst of credential failures strongly indicates potential password guessing success or credential brute-force compromise.',
    legitimate_causes:
      'A user repeatedly typed their password incorrectly before successfully finding and entering their correct password or password manager token.',
    investigation_steps: [
      'Immediately review downstream session activity for this account (e.g. data access, IAM changes, API key creations).',
      'Verify if multi-factor authentication (MFA) was prompted and successfully passed during the authentication.',
      'Reach out directly to the employee via an out-of-band communication channel (Slack/phone) to confirm legitimacy.',
      'If unauthorized, revoke active sessions immediately and trigger an emergency password reset.',
    ],
  },
  TG003: {
    id: 'TG003',
    name: 'Privileged Administrative Role Assignment',
    category: 'Privilege Escalation',
    severity: 'high',
    threshold_summary: 'Explicit role change assigning privileged administrative authority (admin, administrator, root, superuser).',
    rationale:
      'Privilege escalation is a critical phase in attack lifecycles. Gaining administrative authority enables lateral movement, security control tampering, and persistent access.',
    legitimate_causes:
      'Authorized IT administration, planned operational promotions, emergency break-glass procedures, or scheduled IAM role updates tied to approved service requests.',
    investigation_steps: [
      'Verify authorization against approved ITSM change tickets or JIRA access requests.',
      'Confirm whether the actor who granted the role had explicit delegation authority.',
      'Review subsequent actions executed under the elevated role permissions within the next 24 hours.',
      'Ensure the assignment conforms to principle of least privilege (PoLP) and time-bound access limits.',
    ],
  },
  TG004: {
    id: 'TG004',
    name: 'High-Volume or Suspicious Port Egress Transfer',
    category: 'Suspicious Network Transfer',
    severity: 'high',
    threshold_summary: 'Outbound transfer >= 10 MiB (10,485,760 bytes) to a public IP OR outbound connection to ports 4444 or 1337.',
    rationale:
      'Large bulk outbound transfers to external non-reserved addresses may indicate data exfiltration. Dedicated ports 4444 (Metasploit default) and 1337 (hacker slang/leet) are frequently associated with reverse shells or unauthorized tooling.',
    legitimate_causes:
      'Legitimate cloud backup syncs, operating system / container image downloads, large media assets, internal lab test harnesses, or developers running local sandbox services.',
    investigation_steps: [
      'Perform WHOIS and reverse DNS lookup on the public destination IP to identify the hosting entity (AWS, Cloudflare, Azure, ISP).',
      'Correlate the outbound traffic volume with internal application or database access timestamps.',
      'Inspect process trees on the originating host for unusual binaries running network connections on non-standard ports.',
      'Review proxy/firewall packet inspection logs to verify if SSL/TLS certificates match reputable domains.',
    ],
  },
  TG005: {
    id: 'TG005',
    name: 'Sensitive Secret Exposure in Event Payload',
    category: 'Secret Exposure',
    severity: 'critical',
    threshold_summary: 'Detection of private key markers, AWS access keys (AKIA/ASIA), Bearer/JWT tokens, or explicit password assignments in log fields.',
    rationale:
      'Unintentionally logging secrets introduces critical credential leakage into log aggregators, monitoring pipelines, and audit backups where broader access exists.',
    legitimate_causes:
      'Debug logging accidentally enabled in production, legacy error handlers echoing HTTP authorization headers, or testing scripts with hardcoded mock credentials.',
    investigation_steps: [
      'Verify if the exposed credential is active in AWS IAM, Okta, GitHub, or production database environments.',
      'Immediately rotate the affected secret or token in the primary credential vault.',
      'File an urgent engineering bug to patch application log sanitizers and ensure debug parameters are masked at source.',
      'Audit log access history to evaluate who had read access to the centralized log index during the exposure window.',
    ],
  },
};
