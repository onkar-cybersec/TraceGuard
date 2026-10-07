import { describe, expect, it } from 'vitest';
import { BENIGN_DEMO_JSON, TRIGGER_DEMO_JSON } from '../src/data/samples';
import { detectAnomalies } from '../src/engine/detector';
import { isPublicIp, parseIpv4ToUint32, parseIpv6 } from '../src/engine/ipUtils';
import { parseCsvRecords, parseSecurityLogs, validateAndNormalizeEvent, validateIso8601Timestamp } from '../src/engine/parser';
import { redactSecretsInString } from '../src/engine/redaction';
import { escapeHtml, generateRedactedJsonExport, generateSelfContainedHtmlReport } from '../src/engine/reportGenerator';
import { SecurityLogEvent } from '../src/engine/types';

describe('TraceGuard Engine Test Suite', () => {
  // ---------------------------------------------------------------------------
  // 1. IP Utility & Classification
  // ---------------------------------------------------------------------------
  describe('IP Classification (IPv4 & IPv6 Subnet Boundaries)', () => {
    it('classifies public IPv4 addresses correctly', () => {
      expect(isPublicIp('8.8.8.8')).toBe(true);
      expect(isPublicIp('1.1.1.1')).toBe(true);
      expect(isPublicIp('93.184.216.34')).toBe(true);
    });

    it('excludes RFC 1918 private IPv4 ranges', () => {
      expect(isPublicIp('10.0.0.1')).toBe(false);
      expect(isPublicIp('10.255.255.255')).toBe(false);
      expect(isPublicIp('172.16.0.1')).toBe(false);
      expect(isPublicIp('172.31.255.255')).toBe(false);
      expect(isPublicIp('192.168.0.1')).toBe(false);
      expect(isPublicIp('192.168.255.255')).toBe(false);
    });

    it('excludes loopback, link-local, multicast and broadcast IPv4', () => {
      expect(isPublicIp('127.0.0.1')).toBe(false);
      expect(isPublicIp('169.254.1.1')).toBe(false);
      expect(isPublicIp('224.0.0.1')).toBe(false);
      expect(isPublicIp('255.255.255.255')).toBe(false);
    });

    it('excludes RFC 5737 documentation IPv4 addresses', () => {
      expect(isPublicIp('192.0.2.1')).toBe(false);
      expect(isPublicIp('198.51.100.25')).toBe(false);
      expect(isPublicIp('203.0.113.88')).toBe(false);
    });

    it('excludes CGNAT (100.64.0.0/10) and benchmarking (198.18.0.0/15)', () => {
      expect(isPublicIp('100.64.0.1')).toBe(false);
      expect(isPublicIp('100.127.255.254')).toBe(false);
      expect(isPublicIp('198.18.0.5')).toBe(false);
    });

    it('excludes IPv6 private, documentation, loopback, and ULA ranges', () => {
      expect(isPublicIp('::1')).toBe(false); // Loopback
      expect(isPublicIp('::')).toBe(false); // Unspecified
      expect(isPublicIp('2001:db8::1')).toBe(false); // RFC 3849 Documentation
      expect(isPublicIp('fc00::1')).toBe(false); // RFC 4193 ULA
      expect(isPublicIp('fd00:1234::5678')).toBe(false); // RFC 4193 ULA
      expect(isPublicIp('fe80::1')).toBe(false); // Link-Local
      expect(isPublicIp('ff02::1')).toBe(false); // Multicast
    });

    it('classifies public global unicast IPv6 as public', () => {
      expect(isPublicIp('2607:f8b0:4005:805::200e')).toBe(true);
      expect(isPublicIp('2404:6800:4003:c00::64')).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Secret Redaction (TG005)
  // ---------------------------------------------------------------------------
  describe('Secret Redaction (TG005)', () => {
    it('redacts AWS Access Key IDs', () => {
      const input = 'Error contacting bucket with key AKIAIOSFODNN7EXAMPLE in us-east-1';
      const result = redactSecretsInString(input);
      expect(result.sanitized).toContain('[REDACTED_SECRET:AKIA_KEY]');
      expect(result.sanitized).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(result.foundTypes).toContain('AWS Access Key Identifier');
    });

    it('redacts private key blocks', () => {
      const input = 'Cert generated: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY----- finished.';
      const result = redactSecretsInString(input);
      expect(result.sanitized).toContain('[REDACTED_SECRET:PRIVATE_KEY_BLOCK]');
      expect(result.sanitized).not.toContain('MIIEowIBAAKCAQEA0');
    });

    it('redacts Bearer tokens and JWTs', () => {
      const input = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.synthetic_signature_token';
      const result = redactSecretsInString(input);
      expect(result.sanitized).toContain('[REDACTED_SECRET:BEARER_TOKEN]');
      expect(result.sanitized).not.toContain('synthetic_signature_token');
    });

    it('redacts password assignment patterns in strings', () => {
      const input = 'Database connect string: host=db.internal user=root password="SuperSecret123!" port=5432';
      const result = redactSecretsInString(input);
      expect(result.sanitized).toContain('password= [REDACTED_SECRET:PASSWORD]');
      expect(result.sanitized).not.toContain('SuperSecret123!');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Parser & Schema Validation
  // ---------------------------------------------------------------------------
  describe('Parser & Schema Validation', () => {
    it('rejects files exceeding 2 MiB safety limit', () => {
      const largeSize = 2.5 * 1024 * 1024;
      const parsed = parseSecurityLogs('dummy', 'large_log.json', largeSize);
      expect(parsed.success).toBe(false);
      expect(parsed.fatalError).toContain('2 MiB safety limit');
    });

    it('rejects malformed JSON syntax with actionable error', () => {
      const malformedJson = '{ "events": [ { "event_type": "login", } ] }';
      const parsed = parseSecurityLogs(malformedJson, 'broken.json', 100);
      expect(parsed.success).toBe(false);
      expect(parsed.fatalError).toContain('Malformed JSON');
    });

    it('rejects missing timezone in timestamps', () => {
      const badTzJson = JSON.stringify({
        events: [
          {
            event_type: 'login',
            timestamp: '2026-10-07T12:00:00', // Missing Z or offset
          },
        ],
      });
      const parsed = parseSecurityLogs(badTzJson, 'test.json', 100);
      expect(parsed.success).toBe(false);
      expect(parsed.fatalError).toContain('All 1 rows failed schema validation');
    });

    it('processes valid rows and records line-specific errors in mixed datasets', () => {
      const mixedCsv = `event_type,timestamp,user,destination_port
user_login,2026-10-07T12:00:00Z,valid_user,443
user_login,2026-10-07T12:01:00Z,invalid_port_user,99999
,2026-10-07T12:02:00Z,missing_type_user,80
api_access,2026-10-07T12:03:00Z,valid_user_2,8080`;

      const parsed = parseSecurityLogs(mixedCsv, 'mixed.csv', 500);
      expect(parsed.success).toBe(true);
      expect(parsed.validation.valid_count).toBe(2);
      expect(parsed.validation.rejected_count).toBe(2);
      expect(parsed.validation.rejected_rows[0].row_number).toBe(3); // Line 3 has port 99999
      expect(parsed.validation.rejected_rows[0].error).toContain('Destination port must be an integer between 1 and 65535');
      expect(parsed.validation.rejected_rows[1].row_number).toBe(4); // Line 4 has empty event_type
      expect(parsed.validation.rejected_rows[1].error).toContain("Missing required 'event_type'");
    });

    it('handles out-of-order timestamps and sorts chronologically', () => {
      const outOfOrderJson = JSON.stringify({
        events: [
          { event_type: 'login', timestamp: '2026-10-07T12:05:00Z', user: 'bob' },
          { event_type: 'login', timestamp: '2026-10-07T12:01:00Z', user: 'bob' },
          { event_type: 'login', timestamp: '2026-10-07T12:03:00Z', user: 'bob' },
        ],
      });
      const parsed = parseSecurityLogs(outOfOrderJson, 'chrono.json', 150);
      expect(parsed.success).toBe(true);
      expect(parsed.events[0].timestamp).toBe('2026-10-07T12:01:00.000Z');
      expect(parsed.events[1].timestamp).toBe('2026-10-07T12:03:00.000Z');
      expect(parsed.events[2].timestamp).toBe('2026-10-07T12:05:00.000Z');
    });

    it('safely handles script tags and HTML injection without execution', () => {
      const injectionCsv = `event_type,timestamp,user,message
user_login,2026-10-07T12:00:00Z,"<script>alert('xss')</script>","<b>Hello & welcome</b>"`;
      const parsed = parseSecurityLogs(injectionCsv, 'inject.csv', 200);
      expect(parsed.success).toBe(true);
      expect(parsed.events[0].user).toBe("<script>alert('xss')</script>");

      // Verify HTML report escaping
      const escapedUser = escapeHtml(parsed.events[0].user);
      expect(escapedUser).toBe('&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;');
      expect(escapedUser).not.toContain('<script>');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Rule TG001: Failed Authentication Burst
  // ---------------------------------------------------------------------------
  describe('Rule TG001: Failed Authentication Burst', () => {
    const baseTime = 1791350000000; // Reference ms

    it('does NOT trigger with 4 failed authentication events (threshold is 5)', () => {
      const events: SecurityLogEvent[] = [1, 2, 3, 4].map((i) => ({
        id: `evt-${i}`,
        timestamp: new Date(baseTime + i * 30000).toISOString(),
        timestamp_epoch: baseTime + i * 30000,
        event_type: 'login',
        user: 'alice',
        source_ip: '198.51.100.10',
        status: 'failure',
      }));

      const findings = detectAnomalies(events);
      expect(findings.filter((f) => f.rule_id === 'TG001')).toHaveLength(0);
    });

    it('triggers with exactly 5 failed events within 5 minutes', () => {
      const events: SecurityLogEvent[] = [1, 2, 3, 4, 5].map((i) => ({
        id: `evt-${i}`,
        timestamp: new Date(baseTime + i * 40000).toISOString(), // Total 200s < 300s
        timestamp_epoch: baseTime + i * 40000,
        event_type: 'login',
        user: 'alice',
        source_ip: '198.51.100.10',
        status: 'failure',
      }));

      const findings = detectAnomalies(events);
      const tg001Findings = findings.filter((f) => f.rule_id === 'TG001');
      expect(tg001Findings).toHaveLength(1);
      expect(tg001Findings[0].trigger_event_ids).toHaveLength(5);
      expect(tg001Findings[0].entity_user).toBe('alice');
      expect(tg001Findings[0].entity_source_ip).toBe('198.51.100.10');
    });

    it('does NOT trigger if 5 failures are spread out over more than 5 minutes (e.g. 5m01s)', () => {
      const events: SecurityLogEvent[] = [
        {
          id: 'evt-1',
          timestamp: new Date(baseTime).toISOString(),
          timestamp_epoch: baseTime,
          event_type: 'login',
          user: 'alice',
          source_ip: '198.51.100.10',
          status: 'failure',
        },
        {
          id: 'evt-2',
          timestamp: new Date(baseTime + 80000).toISOString(),
          timestamp_epoch: baseTime + 80000,
          event_type: 'login',
          user: 'alice',
          source_ip: '198.51.100.10',
          status: 'failure',
        },
        {
          id: 'evt-3',
          timestamp: new Date(baseTime + 160000).toISOString(),
          timestamp_epoch: baseTime + 160000,
          event_type: 'login',
          user: 'alice',
          source_ip: '198.51.100.10',
          status: 'failure',
        },
        {
          id: 'evt-4',
          timestamp: new Date(baseTime + 240000).toISOString(),
          timestamp_epoch: baseTime + 240000,
          event_type: 'login',
          user: 'alice',
          source_ip: '198.51.100.10',
          status: 'failure',
        },
        {
          id: 'evt-5',
          timestamp: new Date(baseTime + 320000).toISOString(), // 320s > 300s window
          timestamp_epoch: baseTime + 320000,
          event_type: 'login',
          user: 'alice',
          source_ip: '198.51.100.10',
          status: 'failure',
        },
      ];

      const findings = detectAnomalies(events);
      // Window between evt-1 and evt-5 is 320s > 300s. Evt 2..5 is only 4 events. So 0 bursts of 5 within 5m.
      expect(findings.filter((f) => f.rule_id === 'TG001')).toHaveLength(0);
    });

    it('deduplicates continuous overlapping bursts into a single unified incident', () => {
      // 8 rapid failures within 6 minutes
      const events: SecurityLogEvent[] = [1, 2, 3, 4, 5, 6, 7, 8].map((i) => ({
        id: `evt-${i}`,
        timestamp: new Date(baseTime + i * 35000).toISOString(),
        timestamp_epoch: baseTime + i * 35000,
        event_type: 'login',
        user: 'alice',
        source_ip: '198.51.100.10',
        status: 'failure',
      }));

      const findings = detectAnomalies(events);
      const tg001Findings = findings.filter((f) => f.rule_id === 'TG001');
      expect(tg001Findings).toHaveLength(1);
      expect(tg001Findings[0].trigger_event_ids).toHaveLength(8);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Rule TG002: Authentication Success Following Burst
  // ---------------------------------------------------------------------------
  describe('Rule TG002: Authentication Success Following Burst', () => {
    const baseTime = 1791350000000;

    it('triggers when successful login occurs within 10 minutes following 5 failures', () => {
      const failures: SecurityLogEvent[] = [1, 2, 3, 4, 5].map((i) => ({
        id: `fail-${i}`,
        timestamp: new Date(baseTime + i * 30000).toISOString(), // 0 to 150s
        timestamp_epoch: baseTime + i * 30000,
        event_type: 'login',
        user: 'bob',
        source_ip: '203.0.113.20',
        status: 'failure',
      }));

      const success: SecurityLogEvent = {
        id: 'success-1',
        timestamp: new Date(baseTime + 400000).toISOString(), // 400s (6.6 min < 10 min)
        timestamp_epoch: baseTime + 400000,
        event_type: 'login',
        user: 'bob',
        source_ip: '203.0.113.20',
        status: 'success',
      };

      const findings = detectAnomalies([...failures, success]);
      const tg002Findings = findings.filter((f) => f.rule_id === 'TG002');
      expect(tg002Findings).toHaveLength(1);
      expect(tg002Findings[0].trigger_event_ids).toContain('success-1');
      expect(tg002Findings[0].trigger_event_ids).toContain('fail-1');
    });

    it('does NOT trigger if successful login is beyond 10 minutes (e.g. 10m01s)', () => {
      const failures: SecurityLogEvent[] = [1, 2, 3, 4, 5].map((i) => ({
        id: `fail-${i}`,
        timestamp: new Date(baseTime + i * 20000).toISOString(), // 20s to 100s
        timestamp_epoch: baseTime + i * 20000,
        event_type: 'login',
        user: 'bob',
        source_ip: '203.0.113.20',
        status: 'failure',
      }));

      const success: SecurityLogEvent = {
        id: 'success-late',
        timestamp: new Date(baseTime + 750000).toISOString(), // 750s - 100s = 650s > 600s
        timestamp_epoch: baseTime + 750000,
        event_type: 'login',
        user: 'bob',
        source_ip: '203.0.113.20',
        status: 'success',
      };

      const findings = detectAnomalies([...failures, success]);
      expect(findings.filter((f) => f.rule_id === 'TG002')).toHaveLength(0);
    });

    it('strictly isolates unrelated users and unrelated source IPs', () => {
      // 5 failures for user "alice" on IP "1.2.3.4"
      const aliceFailures: SecurityLogEvent[] = [1, 2, 3, 4, 5].map((i) => ({
        id: `alice-${i}`,
        timestamp: new Date(baseTime + i * 20000).toISOString(),
        timestamp_epoch: baseTime + i * 20000,
        event_type: 'login',
        user: 'alice',
        source_ip: '198.51.100.1',
        status: 'failure',
      }));

      // Success for DIFFERENT user "charlie" on same IP
      const charlieSuccess: SecurityLogEvent = {
        id: 'charlie-ok',
        timestamp: new Date(baseTime + 150000).toISOString(),
        timestamp_epoch: baseTime + 150000,
        event_type: 'login',
        user: 'charlie',
        source_ip: '198.51.100.1',
        status: 'success',
      };

      // Success for "alice" but from DIFFERENT source IP
      const aliceOtherIpSuccess: SecurityLogEvent = {
        id: 'alice-diff-ip',
        timestamp: new Date(baseTime + 160000).toISOString(),
        timestamp_epoch: baseTime + 160000,
        event_type: 'login',
        user: 'alice',
        source_ip: '203.0.113.99',
        status: 'success',
      };

      const findings = detectAnomalies([...aliceFailures, charlieSuccess, aliceOtherIpSuccess]);
      // Should NOT trigger TG002 for charlie or alice from different IP
      expect(findings.filter((f) => f.rule_id === 'TG002')).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Rule TG003: Privileged Role Change
  // ---------------------------------------------------------------------------
  describe('Rule TG003: Administrative Role Assignment', () => {
    it('triggers for admin, administrator, root, superuser (case-insensitive)', () => {
      const roles = ['Administrator', 'ADMIN', 'root', 'SuperUser'];
      roles.forEach((r, idx) => {
        const evt: SecurityLogEvent = {
          id: `role-${idx}`,
          timestamp: '2026-10-07T12:00:00Z',
          timestamp_epoch: 1791350000000 + idx * 1000,
          event_type: 'iam_change',
          user: `user-${idx}`,
          new_role: r,
          status: 'success',
        };
        const findings = detectAnomalies([evt]);
        expect(findings.filter((f) => f.rule_id === 'TG003')).toHaveLength(1);
      });
    });

    it('does NOT trigger for standard non-privileged roles', () => {
      const benignRoles = ['viewer', 'billing_analyst', 'editor', 'developer', 'tester'];
      benignRoles.forEach((r, idx) => {
        const evt: SecurityLogEvent = {
          id: `role-benign-${idx}`,
          timestamp: '2026-10-07T12:00:00Z',
          timestamp_epoch: 1791350000000 + idx * 1000,
          event_type: 'iam_change',
          user: `user-${idx}`,
          new_role: r,
          status: 'success',
        };
        const findings = detectAnomalies([evt]);
        expect(findings.filter((f) => f.rule_id === 'TG003')).toHaveLength(0);
      });
    });
  });

  // ---------------------------------------------------------------------------
  // 7. Rule TG004: Suspicious Network Egress
  // ---------------------------------------------------------------------------
  describe('Rule TG004: Suspicious Network Egress', () => {
    const PUBLIC_DEST = '93.184.216.34';
    const PRIVATE_DEST = '10.0.1.50';
    const DOC_DEST = '198.51.100.5';

    it('triggers on >= 10 MiB to public IP', () => {
      const evt: SecurityLogEvent = {
        id: 'egress-1',
        timestamp: '2026-10-07T12:00:00Z',
        timestamp_epoch: 1791350000000,
        event_type: 'egress',
        destination_ip: PUBLIC_DEST,
        destination_port: 443,
        bytes: 10485760, // Exactly 10 MiB
      };
      const findings = detectAnomalies([evt]);
      expect(findings.filter((f) => f.rule_id === 'TG004')).toHaveLength(1);
    });

    it('does NOT trigger if bytes is 1 byte below 10 MiB (10,485,759) on normal port', () => {
      const evt: SecurityLogEvent = {
        id: 'egress-sub',
        timestamp: '2026-10-07T12:00:00Z',
        timestamp_epoch: 1791350000000,
        event_type: 'egress',
        destination_ip: PUBLIC_DEST,
        destination_port: 443,
        bytes: 10485759,
      };
      const findings = detectAnomalies([evt]);
      expect(findings.filter((f) => f.rule_id === 'TG004')).toHaveLength(0);
    });

    it('does NOT trigger for 100 MiB transfer to RFC 1918 private or doc IPs', () => {
      const privateEvt: SecurityLogEvent = {
        id: 'egress-priv',
        timestamp: '2026-10-07T12:00:00Z',
        timestamp_epoch: 1791350000000,
        event_type: 'egress',
        destination_ip: PRIVATE_DEST,
        destination_port: 443,
        bytes: 100000000, // 100 MB
      };
      const docEvt: SecurityLogEvent = {
        id: 'egress-doc',
        timestamp: '2026-10-07T12:00:00Z',
        timestamp_epoch: 1791350000000,
        event_type: 'egress',
        destination_ip: DOC_DEST,
        destination_port: 443,
        bytes: 100000000, // 100 MB
      };
      const findings = detectAnomalies([privateEvt, docEvt]);
      expect(findings.filter((f) => f.rule_id === 'TG004')).toHaveLength(0);
    });

    it('triggers on ports 4444 and 1337 even with minimal bytes', () => {
      const p4444: SecurityLogEvent = {
        id: 'port-4444',
        timestamp: '2026-10-07T12:00:00Z',
        timestamp_epoch: 1791350000000,
        event_type: 'connection',
        destination_port: 4444,
        bytes: 120,
      };
      const p1337: SecurityLogEvent = {
        id: 'port-1337',
        timestamp: '2026-10-07T12:00:00Z',
        timestamp_epoch: 1791350000000,
        event_type: 'connection',
        destination_port: 1337,
        bytes: 250,
      };
      const findings = detectAnomalies([p4444, p1337]);
      expect(findings.filter((f) => f.rule_id === 'TG004')).toHaveLength(2);
    });
  });

  // ---------------------------------------------------------------------------
  // 8. End-to-End Datasets
  // ---------------------------------------------------------------------------
  describe('Full Sample Benchmark Datasets', () => {
    it('TRIGGER_DEMO_JSON triggers all 5 rules (TG001..TG005)', () => {
      const parsed = parseSecurityLogs(TRIGGER_DEMO_JSON, 'trigger_demo.json', TRIGGER_DEMO_JSON.length);
      expect(parsed.success).toBe(true);

      const findings = detectAnomalies(parsed.events);
      const ruleIds = new Set(findings.map((f) => f.rule_id));

      expect(ruleIds.has('TG001')).toBe(true);
      expect(ruleIds.has('TG002')).toBe(true);
      expect(ruleIds.has('TG003')).toBe(true);
      expect(ruleIds.has('TG004')).toBe(true);
      expect(ruleIds.has('TG005')).toBe(true);
    });

    it('BENIGN_DEMO_JSON produces ZERO findings and disclaims full security', () => {
      const parsed = parseSecurityLogs(BENIGN_DEMO_JSON, 'benign_demo.json', BENIGN_DEMO_JSON.length);
      expect(parsed.success).toBe(true);

      const findings = detectAnomalies(parsed.events);
      expect(findings).toHaveLength(0);

      // Verify report generator disclaimer on 0 findings
      const htmlReport = generateSelfContainedHtmlReport(parsed.validation, findings);
      expect(htmlReport).toContain('The absence of triggered findings');
      expect(htmlReport).toContain('prove that the audited system is secure');
    });
  });

  // ---------------------------------------------------------------------------
  // 9. Regression Suite: Filtered Findings UI Consistency
  // ---------------------------------------------------------------------------
  describe('Regression: Filtered Findings Consistency Across Metrics, Categories, Entities & Timeline', () => {
    it('ensures filtering by TG005 properly drives severity breakdown, categories, affected entities, and timeline evidence', () => {
      const parsed = parseSecurityLogs(TRIGGER_DEMO_JSON, 'trigger_demo.json', TRIGGER_DEMO_JSON.length);
      expect(parsed.success).toBe(true);
      expect(parsed.validation.valid_count).toBe(21);
      expect(parsed.validation.total_rows).toBe(21);
      expect(parsed.validation.rejected_count).toBe(0);

      const allFindings = detectAnomalies(parsed.events);
      expect(allFindings).toHaveLength(8);

      // Global breakdown
      const globalCrit = allFindings.filter((f) => f.severity === 'critical').length;
      const globalHigh = allFindings.filter((f) => f.severity === 'high').length;
      const globalMed = allFindings.filter((f) => f.severity === 'medium').length;
      expect(globalCrit).toBe(3);
      expect(globalHigh).toBe(3);
      expect(globalMed).toBe(2);

      // Filter by TG005 (Secret Exposure)
      const selectedRule = 'TG005';
      const filteredFindings = allFindings.filter((f) => f.rule_id === selectedRule);
      expect(filteredFindings).toHaveLength(2);

      // 1. Filtered Severity Breakdown must NOT remain global (3/3/2)
      const filteredCrit = filteredFindings.filter((f) => f.severity === 'critical').length;
      const filteredHigh = filteredFindings.filter((f) => f.severity === 'high').length;
      const filteredMed = filteredFindings.filter((f) => f.severity === 'medium').length;
      const filteredLow = filteredFindings.filter((f) => f.severity === 'low').length;

      expect(filteredCrit).toBe(2);
      expect(filteredHigh).toBe(0); // High must be 0, not 3!
      expect(filteredMed).toBe(0); // Med must be 0, not 2!
      expect(filteredLow).toBe(0);

      // 2. Filtered Category Distribution must strictly reflect filtered findings
      const secretExposureCount = filteredFindings.filter((f) => f.category === 'Secret Exposure').length;
      const credAttackCount = filteredFindings.filter((f) => f.category === 'Credential Attack').length;
      const accountCompromiseCount = filteredFindings.filter((f) => f.category === 'Account Compromise').length;

      expect(secretExposureCount).toBe(2);
      expect(credAttackCount).toBe(0);
      expect(accountCompromiseCount).toBe(0);

      // 3. Filtered Affected Entities must ONLY contain entities from TG005
      const affectedIps = new Set<string>();
      const affectedUsers = new Set<string>();
      filteredFindings.forEach((f) => {
        if (f.entity_source_ip) affectedIps.add(f.entity_source_ip);
        if (f.entity_user) affectedUsers.add(f.entity_user);
      });

      // TG005 entities
      expect(affectedIps.has('10.0.1.99')).toBe(true);
      expect(affectedIps.has('10.0.2.15')).toBe(true);
      expect(affectedUsers.has('ci_pipeline_bot')).toBe(true);
      expect(affectedUsers.has('app_backend')).toBe(true);

      // MUST NOT contain entities from TG001, TG002, TG003, or TG004
      expect(affectedIps.has('198.51.100.45')).toBe(false); // TG001 IP
      expect(affectedIps.has('203.0.113.88')).toBe(false); // TG002 IP
      expect(affectedIps.has('10.0.1.44')).toBe(false); // TG003 IP
      expect(affectedUsers.has('j.miller')).toBe(false); // TG001 user
      expect(affectedUsers.has('alex.chen')).toBe(false); // TG002 user
      expect(affectedUsers.has('m.rodriguez')).toBe(false); // TG003 user

      // 4. Timeline Flagged Evidence Events must ONLY reflect filtered findings
      const flaggedEventIds = new Set<string>();
      filteredFindings.forEach((f) => {
        f.trigger_event_ids.forEach((id) => flaggedEventIds.add(id));
      });

      // TG005 events are evt-20 and evt-21
      expect(flaggedEventIds.size).toBe(2);

      // 5. Source Event Metrics remain explicitly global
      expect(parsed.validation.total_rows).toBe(21);
      expect(parsed.validation.valid_count).toBe(21);
      expect(parsed.validation.rejected_count).toBe(0);
    });

    it('verifies timeline bars for both trigger and benign datasets have strictly nonzero heights for active buckets', () => {
      // 1. Test trigger dataset timeline
      const triggerParsed = parseSecurityLogs(TRIGGER_DEMO_JSON, 'trigger_demo.json', TRIGGER_DEMO_JSON.length);
      expect(triggerParsed.success).toBe(true);

      const minEpoch = triggerParsed.events[0].timestamp_epoch;
      const maxEpoch = triggerParsed.events[triggerParsed.events.length - 1].timestamp_epoch;
      const spanMs = Math.max(maxEpoch - minEpoch, 1000);
      const numBuckets = Math.min(Math.max(Math.floor(triggerParsed.events.length / 2), 6), 18);
      const bucketInterval = spanMs / numBuckets;

      const triggerCounts = new Array(numBuckets).fill(0);
      triggerParsed.events.forEach((evt) => {
        let idx = Math.floor((evt.timestamp_epoch - minEpoch) / bucketInterval);
        if (idx >= numBuckets) idx = numBuckets - 1;
        if (idx < 0) idx = 0;
        triggerCounts[idx]++;
      });

      const maxTrigger = Math.max(...triggerCounts, 1);
      const activeTriggerHeights = triggerCounts
        .filter((c) => c > 0)
        .map((c) => Math.max(Math.round((c / maxTrigger) * 92), 10));

      expect(activeTriggerHeights.length).toBeGreaterThan(0);
      activeTriggerHeights.forEach((h) => {
        expect(h).toBeGreaterThanOrEqual(10); // Minimum 10px definite height
      });

      // 2. Test benign baseline dataset timeline
      const benignParsed = parseSecurityLogs(BENIGN_DEMO_JSON, 'benign_demo.json', BENIGN_DEMO_JSON.length);
      expect(benignParsed.success).toBe(true);

      const bMin = benignParsed.events[0].timestamp_epoch;
      const bMax = benignParsed.events[benignParsed.events.length - 1].timestamp_epoch;
      const bSpan = Math.max(bMax - bMin, 1000);
      const bNum = Math.min(Math.max(Math.floor(benignParsed.events.length / 2), 6), 18);
      const bInterval = bSpan / bNum;

      const benignCounts = new Array(bNum).fill(0);
      benignParsed.events.forEach((evt) => {
        let idx = Math.floor((evt.timestamp_epoch - bMin) / bInterval);
        if (idx >= bNum) idx = bNum - 1;
        if (idx < 0) idx = 0;
        benignCounts[idx]++;
      });

      const maxBenign = Math.max(...benignCounts, 1);
      const activeBenignHeights = benignCounts
        .filter((c) => c > 0)
        .map((c) => Math.max(Math.round((c / maxBenign) * 92), 10));

      expect(activeBenignHeights.length).toBeGreaterThan(0);
      activeBenignHeights.forEach((h) => {
        expect(h).toBeGreaterThanOrEqual(10); // Minimum 10px definite height
      });
    });
  });

  // ---------------------------------------------------------------------------
  // 10. Pre-Release Bug Regression: Secret Scrubbing in UI Parse Results & Reports
  // ---------------------------------------------------------------------------
  describe('Regression: Complete Secret Redaction Across Parse Errors, Rejected Rows, and Reports', () => {
    const FAKE_AWS_TOKEN = 'AKIAIOSFODNN7EXAMPLE';
    const FAKE_PASS_TOKEN = 'SuperSecretPass123!';
    const FAKE_BEARER_TOKEN = 'Bearer synthetic_secret_token_1234567890abcdef';

    it('ensures mixed valid + invalid JSON rows scrub secrets from rejected previews, errors, and exports', () => {
      const mixedJson = JSON.stringify({
        events: [
          // Valid row with secret in message
          {
            event_type: 'user_login',
            timestamp: '2026-10-07T12:00:00Z',
            user: 'alice',
            message: `Logged in using key ${FAKE_AWS_TOKEN}`,
          },
          // Invalid row (invalid timestamp) with secret in password assignment
          {
            event_type: 'auth_attempt',
            timestamp: 'invalid-timestamp-value',
            user: 'bob',
            password: FAKE_PASS_TOKEN,
          },
        ],
      });

      const parsed = parseSecurityLogs(mixedJson, 'test_mixed.json', 500);
      expect(parsed.success).toBe(true);
      expect(parsed.validation.valid_count).toBe(1);
      expect(parsed.validation.rejected_count).toBe(1);

      // Verify rejected row preview and error never expose raw secret
      const rejectedRow = parsed.validation.rejected_rows[0];
      expect(rejectedRow.raw_content).not.toContain(FAKE_PASS_TOKEN);
      expect(rejectedRow.raw_content).toContain('[REDACTED_SECRET:');
      expect(rejectedRow.error).not.toContain(FAKE_PASS_TOKEN);

      // Verify findings and exports
      const findings = detectAnomalies(parsed.events);
      const jsonExport = generateRedactedJsonExport({
        events: parsed.events,
        findings,
        validation: parsed.validation,
      });

      expect(jsonExport).not.toContain(FAKE_AWS_TOKEN);
      expect(jsonExport).not.toContain(FAKE_PASS_TOKEN);

      const htmlReport = generateSelfContainedHtmlReport(parsed.validation, findings);
      expect(htmlReport).not.toContain(FAKE_AWS_TOKEN);
      expect(htmlReport).not.toContain(FAKE_PASS_TOKEN);
    });

    it('ensures mixed valid + invalid CSV rows scrub secrets from rejected previews and reports', () => {
      const mixedCsv = `event_type,timestamp,user,password,destination_port
user_login,2026-10-07T12:00:00Z,valid_user,${FAKE_PASS_TOKEN},443
user_login,2026-10-07T12:01:00Z,bad_port_user,${FAKE_PASS_TOKEN},99999`;

      const parsed = parseSecurityLogs(mixedCsv, 'mixed_secrets.csv', 500);
      expect(parsed.success).toBe(true);
      expect(parsed.validation.valid_count).toBe(1);
      expect(parsed.validation.rejected_count).toBe(1);

      const rejected = parsed.validation.rejected_rows[0];
      expect(rejected.raw_content).not.toContain(FAKE_PASS_TOKEN);
      expect(rejected.raw_content).toContain('[REDACTED_SECRET:PASSWORD]');
      expect(rejected.error).not.toContain(FAKE_PASS_TOKEN);

      const findings = detectAnomalies(parsed.events);
      const jsonExport = generateRedactedJsonExport({
        events: parsed.events,
        findings,
        validation: parsed.validation,
      });
      expect(jsonExport).not.toContain(FAKE_PASS_TOKEN);

      const htmlReport = generateSelfContainedHtmlReport(parsed.validation, findings);
      expect(htmlReport).not.toContain(FAKE_PASS_TOKEN);
    });

    it('sanitizes input excerpts in malformed JSON parser errors', () => {
      // Malformed JSON containing secret token before the syntax error
      const badJson = `{ "events": [ { "token": "${FAKE_AWS_TOKEN}", } ] }`;
      const parsed = parseSecurityLogs(badJson, 'malformed.json', 200);

      expect(parsed.success).toBe(false);
      expect(parsed.fatalError).toBeDefined();
      expect(parsed.fatalError).not.toContain(FAKE_AWS_TOKEN);
    });

    it('sanitizes input excerpts and filenames in CSV errors', () => {
      // Unterminated quote containing fake secret
      const badCsv = `event_type,timestamp,token\nlogin,2026-10-07T12:00:00Z,"${FAKE_BEARER_TOKEN}`;
      const parsed = parseSecurityLogs(badCsv, `audit_${FAKE_AWS_TOKEN}.csv`, 200);

      expect(parsed.success).toBe(false);
      expect(parsed.fatalError).toBeDefined();
      expect(parsed.fatalError).not.toContain(FAKE_BEARER_TOKEN);
      expect(parsed.validation.file_name).not.toContain(FAKE_AWS_TOKEN);
    });
  });

  // ---------------------------------------------------------------------------
  // 11. Pre-Release Bug Regression: Strict RFC 4180 CSV State Enforcement
  // ---------------------------------------------------------------------------
  describe('Regression: Strict RFC 4180 CSV State Enforcement', () => {
    it('rejects unterminated quotes at EOF', () => {
      const csv = `event_type,timestamp\nuser_login,"2026-10-07T12:00:00Z`;
      const result = parseCsvRecords(csv);
      expect(result.error).toContain('Unterminated quote in CSV record');
    });

    it('rejects quotes inside unquoted fields', () => {
      const csv = `event_type,timestamp\nuser_log"in,2026-10-07T12:00:00Z`;
      const result = parseCsvRecords(csv);
      expect(result.error).toContain('Unexpected quote character inside unquoted field');
    });

    it('rejects trailing characters after closing quote', () => {
      const csv = `event_type,timestamp\n"user_login"junk,2026-10-07T12:00:00Z`;
      const result = parseCsvRecords(csv);
      expect(result.error).toContain('Trailing characters found after closing quote');
    });

    it('correctly parses and retains multiline quoted fields', () => {
      const csv = `event_type,timestamp,message\nuser_login,2026-10-07T12:00:00Z,"Line 1\nLine 2\nLine 3"`;
      const result = parseCsvRecords(csv);
      expect(result.error).toBeUndefined();
      expect(result.records).toHaveLength(2);
      expect(result.records[1][2]).toBe('Line 1\nLine 2\nLine 3');
    });

    it('rejects duplicate column headers in CSV files', () => {
      const csv = `event_type,timestamp,user,USER\nlogin,2026-10-07T12:00:00Z,alice,alice`;
      const parsed = parseSecurityLogs(csv, 'dup.csv', 100);
      expect(parsed.success).toBe(false);
      expect(parsed.fatalError).toContain('Duplicate column header');
    });

    it('records errors for rows with mismatched column counts', () => {
      const csv = `event_type,timestamp,user\nlogin,2026-10-07T12:00:00Z,alice\nlogin,2026-10-07T12:01:00Z`;
      const parsed = parseSecurityLogs(csv, 'cols.csv', 100);
      expect(parsed.success).toBe(true);
      expect(parsed.validation.valid_count).toBe(1);
      expect(parsed.validation.rejected_count).toBe(1);
      expect(parsed.validation.rejected_rows[0].error).toContain('expected 3 columns');
    });
  });

  // ---------------------------------------------------------------------------
  // 12. Pre-Release Bug Regression: Strict Calendar Date Validation
  // ---------------------------------------------------------------------------
  describe('Regression: Strict Calendar Date & Time Validation', () => {
    it('rejects impossible calendar dates without silent normalization (e.g. 2026-02-30, 2026-04-31)', () => {
      const feb30 = validateIso8601Timestamp('2026-02-30T12:00:00Z');
      expect(feb30.valid).toBe(false);
      expect(feb30.error).toContain('Calendar day 30 is invalid for February');

      const apr31 = validateIso8601Timestamp('2026-04-31T12:00:00Z');
      expect(apr31.valid).toBe(false);
      expect(apr31.error).toContain('Calendar day 31 is invalid for April');

      // Non-leap year February 29
      const feb29NonLeap = validateIso8601Timestamp('2026-02-29T12:00:00Z');
      expect(feb29NonLeap.valid).toBe(false);
      expect(feb29NonLeap.error).toContain('max 28 days');

      // Valid leap year February 29
      const feb29Leap = validateIso8601Timestamp('2024-02-29T12:00:00Z');
      expect(feb29Leap.valid).toBe(true);
    });

    it('rejects out-of-range hours, minutes, and seconds', () => {
      expect(validateIso8601Timestamp('2026-10-07T24:00:00Z').valid).toBe(false);
      expect(validateIso8601Timestamp('2026-10-07T12:60:00Z').valid).toBe(false);
      expect(validateIso8601Timestamp('2026-10-07T12:00:60Z').valid).toBe(false);
    });

    it('rejects invalid timezone offset hours and minutes', () => {
      expect(validateIso8601Timestamp('2026-10-07T12:00:00+15:00').valid).toBe(false);
      expect(validateIso8601Timestamp('2026-10-07T12:00:00+05:65').valid).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // 13. Pre-Release Bug Regression: Strict Numeric Bounds (Bytes & Port)
  // ---------------------------------------------------------------------------
  describe('Regression: Strict Numeric Bounds for Bytes and Port', () => {
    it('rejects Infinity, negative, fractional, and non-numeric values for bytes', () => {
      // 1. Direct validation tests for JavaScript numeric edge cases (Infinity, -Infinity, NaN)
      const infResult = validateAndNormalizeEvent(
        { event_type: 'transfer', timestamp: '2026-10-07T12:00:00Z', bytes: Infinity },
        'evt-inf'
      );
      expect(infResult.event).toBeUndefined();
      expect(infResult.error).toContain('Bytes transferred must be a finite non-negative integer without fractions');

      const negInfResult = validateAndNormalizeEvent(
        { event_type: 'transfer', timestamp: '2026-10-07T12:00:00Z', bytes: -Infinity },
        'evt-neginf'
      );
      expect(negInfResult.event).toBeUndefined();
      expect(negInfResult.error).toContain('Bytes transferred must be a finite non-negative integer without fractions');

      const nanResult = validateAndNormalizeEvent(
        { event_type: 'transfer', timestamp: '2026-10-07T12:00:00Z', bytes: NaN },
        'evt-nan'
      );
      expect(nanResult.event).toBeUndefined();
      expect(nanResult.error).toContain('Bytes transferred must be a finite non-negative integer without fractions');

      // 2. JSON log ingestion tests (fractions, negative, string fractions, booleans, arrays, string "Infinity")
      const cases = [
        { bytes: 'Infinity', desc: 'string Infinity' },
        { bytes: 10.5, desc: 'fractional number' },
        { bytes: '12.34', desc: 'fractional string' },
        { bytes: -50, desc: 'negative number' },
        { bytes: true, desc: 'boolean' },
        { bytes: [100], desc: 'array' },
      ];

      cases.forEach(({ bytes, desc }) => {
        const json = JSON.stringify({
          events: [
            {
              event_type: 'transfer',
              timestamp: '2026-10-07T12:00:00Z',
              bytes,
            },
          ],
        });
        const parsed = parseSecurityLogs(json, `bytes_${desc}.json`, 100);
        expect(parsed.success).toBe(false);
        expect(parsed.fatalError).toContain('All 1 rows failed schema validation');
      });
    });

    it('accepts valid 0 and large safe positive integers for bytes', () => {
      const json = JSON.stringify({
        events: [
          { event_type: 'transfer', timestamp: '2026-10-07T12:00:00Z', bytes: 0 },
          { event_type: 'transfer', timestamp: '2026-10-07T12:01:00Z', bytes: 10485760 },
        ],
      });
      const parsed = parseSecurityLogs(json, 'valid_bytes.json', 100);
      expect(parsed.success).toBe(true);
      expect(parsed.events[0].bytes).toBe(0);
      expect(parsed.events[1].bytes).toBe(10485760);
    });

    it('rejects invalid destination port values (fractions, 0, >65535, booleans, arrays, Infinity)', () => {
      // 1. Direct validation for Infinity
      const portInf = validateAndNormalizeEvent(
        { event_type: 'conn', timestamp: '2026-10-07T12:00:00Z', destination_port: Infinity },
        'evt-port-inf'
      );
      expect(portInf.event).toBeUndefined();
      expect(portInf.error).toContain('Destination port must be an integer between 1 and 65535');

      // 2. JSON log ingestion tests
      const badPorts = [0, 65536, 80.5, '443.2', -1, true, [80], 'Infinity'];

      badPorts.forEach((destination_port) => {
        const json = JSON.stringify({
          events: [
            {
              event_type: 'conn',
              timestamp: '2026-10-07T12:00:00Z',
              destination_port,
            },
          ],
        });
        const parsed = parseSecurityLogs(json, 'bad_port.json', 100);
        expect(parsed.success).toBe(false);
        expect(parsed.fatalError).toContain('All 1 rows failed schema validation');
      });
    });
  });
});