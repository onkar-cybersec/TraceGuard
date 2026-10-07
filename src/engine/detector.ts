import { isPublicIp } from './ipUtils';
import { RULE_DEFINITIONS } from './rules';
import { DetectionFinding, SecurityLogEvent } from './types';

// Helper to determine if an event is an authentication failure
export function isAuthFailure(event: SecurityLogEvent): boolean {
  const normType = event.event_type.toLowerCase();
  const normStatus = (event.status || '').toLowerCase();

  const isFailureStatus = ['failure', 'failed', 'fail', 'denied', 'unauthorized', 'error', '401', '403'].includes(normStatus);
  const isAuthType = /auth|login|signin|credential|session|token/.test(normType);

  if (isAuthType && isFailureStatus) return true;
  if (/login_fail|auth_fail|failed_login|authentication_fail|signin_fail/.test(normType)) return true;

  return false;
}

// Helper to determine if an event is an authentication success
export function isAuthSuccess(event: SecurityLogEvent): boolean {
  const normType = event.event_type.toLowerCase();
  const normStatus = (event.status || '').toLowerCase();

  const isSuccessStatus = ['success', 'succeeded', 'ok', 'allowed', 'accepted', '200'].includes(normStatus);
  const isAuthType = /auth|login|signin|credential|session/.test(normType);

  if (isAuthType && isSuccessStatus) return true;
  if (/login_success|auth_success|successful_login|authentication_success|signin_success/.test(normType)) return true;

  return false;
}

// Check if new_role or message assigns administrative/root privileges
export function isPrivilegedRoleAssignment(event: SecurityLogEvent): { matched: boolean; assignedRole?: string } {
  const adminPattern = /\b(admin|administrator|root|superuser)\b/i;

  if (event.new_role && adminPattern.test(event.new_role)) {
    return { matched: true, assignedRole: event.new_role };
  }

  const normType = event.event_type.toLowerCase();
  const isRoleEventType = /role|privilege|permission|iam|grant|group|membership/.test(normType);

  if (isRoleEventType && event.message && adminPattern.test(event.message)) {
    const match = event.message.match(adminPattern);
    return { matched: true, assignedRole: match ? match[0] : 'admin' };
  }

  // Also check raw role field if present
  if (event.raw && typeof event.raw.role === 'string' && adminPattern.test(event.raw.role)) {
    return { matched: true, assignedRole: event.raw.role };
  }

  return { matched: false };
}

const TG001_WINDOW_MS = 5 * 60 * 1000; // 5 minutes (300,000 ms)
const TG001_MIN_FAILURES = 5;

const TG002_WINDOW_MS = 10 * 60 * 1000; // 10 minutes (600,000 ms)
const TG002_MIN_FAILURES = 5;

const TG004_EGRESS_THRESHOLD_BYTES = 10 * 1024 * 1024; // 10 MiB (10,485,760 bytes)
const TG004_SUSPICIOUS_PORTS = [4444, 1337];

/**
 * Execute all 5 deterministic correlation rules on normalized events.
 */
export function detectAnomalies(events: SecurityLogEvent[]): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  let findingCounter = 1;

  // Chronologically sorted events
  const sortedEvents = [...events].sort((a, b) => a.timestamp_epoch - b.timestamp_epoch);

  // Group events by identity key for stateful correlation: `${user || 'NO_USER'}:::${source_ip || 'NO_IP'}`
  const userIpGroups = new Map<string, SecurityLogEvent[]>();

  sortedEvents.forEach((evt) => {
    if (evt.user && evt.source_ip) {
      const key = `${evt.user}:::${evt.source_ip}`;
      if (!userIpGroups.has(key)) {
        userIpGroups.set(key, []);
      }
      userIpGroups.get(key)!.push(evt);
    }
  });

  // =========================================================================
  // RULE TG001: 5+ failed auth events for same source IP AND user in rolling 5m window
  // Deduplicate overlapping windows and retain all supporting event IDs.
  // =========================================================================
  const tg001Rule = RULE_DEFINITIONS.TG001;

  userIpGroups.forEach((groupEvents, key) => {
    const [user, sourceIp] = key.split(':::');
    const authFailures = groupEvents.filter(isAuthFailure);
    if (authFailures.length < TG001_MIN_FAILURES) return;

    // Find all qualifying 5-minute slices with >= 5 events
    const qualifyingIntervals: Array<{ startIdx: number; endIdx: number }> = [];

    for (let i = 0; i <= authFailures.length - TG001_MIN_FAILURES; i++) {
      // Find the furthest event j where timestamp - start <= 5 minutes
      const windowStart = authFailures[i].timestamp_epoch;
      let j = i;
      while (j < authFailures.length && authFailures[j].timestamp_epoch - windowStart <= TG001_WINDOW_MS) {
        j++;
      }
      // Number of events in [i, j - 1] is j - i
      if (j - i >= TG001_MIN_FAILURES) {
        qualifyingIntervals.push({ startIdx: i, endIdx: j - 1 });
      }
    }

    if (qualifyingIntervals.length === 0) return;

    // Merge overlapping intervals to deduplicate findings
    const mergedIntervals: Array<{ startIdx: number; endIdx: number }> = [];
    let currentMerged = { ...qualifyingIntervals[0] };

    for (let k = 1; k < qualifyingIntervals.length; k++) {
      const nextInterval = qualifyingIntervals[k];
      if (nextInterval.startIdx <= currentMerged.endIdx) {
        currentMerged.endIdx = Math.max(currentMerged.endIdx, nextInterval.endIdx);
      } else {
        mergedIntervals.push(currentMerged);
        currentMerged = { ...nextInterval };
      }
    }
    mergedIntervals.push(currentMerged);

    // Convert merged intervals to findings
    mergedIntervals.forEach((interval) => {
      const burst = authFailures.slice(interval.startIdx, interval.endIdx + 1);
      const eventIds = burst.map((e) => e.id);
      findings.push({
        id: `FND-TG001-${findingCounter++}`,
        rule_id: 'TG001',
        rule_title: tg001Rule.name,
        category: tg001Rule.category,
        severity: tg001Rule.severity,
        summary: `Detected burst of ${burst.length} consecutive authentication failures for account "${user}" from ${sourceIp} within 5 minutes.`,
        explanation: `A burst of ${burst.length} failed login attempts was observed between ${burst[0].timestamp} and ${burst[burst.length - 1].timestamp}. The rolling 5-minute threshold (>= 5 failures) was exceeded. Overlapping windows have been unified into this incident trace.`,
        entity_source_ip: sourceIp,
        entity_user: user,
        trigger_event_ids: eventIds,
        first_seen_utc: burst[0].timestamp,
        last_seen_utc: burst[burst.length - 1].timestamp,
        supporting_events: burst,
        suggested_investigation_steps: tg001Rule.investigation_steps,
        caveat_notice: `Legitimate possible causes: ${tg001Rule.legitimate_causes}`,
      });
    });
  });

  // =========================================================================
  // RULE TG002: Successful login following 5+ failures for same source/user in preceding 10m
  // Do not correlate unrelated users or IPs.
  // =========================================================================
  const tg002Rule = RULE_DEFINITIONS.TG002;

  userIpGroups.forEach((groupEvents, key) => {
    const [user, sourceIp] = key.split(':::');

    for (let i = 0; i < groupEvents.length; i++) {
      const evt = groupEvents[i];

      if (isAuthSuccess(evt)) {
        // Look back up to 10 minutes (600,000 ms) for failed events from the EXACT same user & source_ip
        const windowStartTime = evt.timestamp_epoch - TG002_WINDOW_MS;
        const precedingFailures = groupEvents
          .slice(0, i)
          .filter((prev) => prev.timestamp_epoch >= windowStartTime && prev.timestamp_epoch <= evt.timestamp_epoch && isAuthFailure(prev));

        if (precedingFailures.length >= TG002_MIN_FAILURES) {
          const supporting = [...precedingFailures, evt];
          const eventIds = supporting.map((e) => e.id);

          findings.push({
            id: `FND-TG002-${findingCounter++}`,
            rule_id: 'TG002',
            rule_title: tg002Rule.name,
            category: tg002Rule.category,
            severity: tg002Rule.severity,
            summary: `Successful authentication for "${user}" from ${sourceIp} directly following ${precedingFailures.length} failures within 10 minutes.`,
            explanation: `Account "${user}" logged in successfully at ${evt.timestamp} from ${sourceIp} after suffering ${precedingFailures.length} failed attempts in the preceding 10-minute window. This behavioral pattern indicates potential credential compromise or brute-force success.`,
            entity_source_ip: sourceIp,
            entity_user: user,
            trigger_event_ids: eventIds,
            first_seen_utc: precedingFailures[0].timestamp,
            last_seen_utc: evt.timestamp,
            supporting_events: supporting,
            suggested_investigation_steps: tg002Rule.investigation_steps,
            caveat_notice: `Legitimate possible causes: ${tg002Rule.legitimate_causes}`,
          });
        }
      }
    }
  });

  // =========================================================================
  // RULE TG003: Explicit role/privilege-change assigning admin/administrator/root/superuser
  // Flag for review and state it might be approved.
  // =========================================================================
  const tg003Rule = RULE_DEFINITIONS.TG003;

  sortedEvents.forEach((evt) => {
    const { matched, assignedRole } = isPrivilegedRoleAssignment(evt);
    if (matched) {
      findings.push({
        id: `FND-TG003-${findingCounter++}`,
        rule_id: 'TG003',
        rule_title: tg003Rule.name,
        category: tg003Rule.category,
        severity: tg003Rule.severity,
        summary: `Privileged role "${assignedRole || 'admin'}" assigned to entity "${evt.user || 'Unknown User'}".`,
        explanation: `An explicit role change event (${evt.event_type}) assigned administrative authority ("${assignedRole || 'admin'}") at ${evt.timestamp}. Privileged promotions require verification against authorized change control records.`,
        entity_source_ip: evt.source_ip,
        entity_user: evt.user,
        trigger_event_ids: [evt.id],
        first_seen_utc: evt.timestamp,
        last_seen_utc: evt.timestamp,
        supporting_events: [evt],
        suggested_investigation_steps: tg003Rule.investigation_steps,
        caveat_notice: `Notice: This assignment may represent authorized IT maintenance, planned administrative elevation, or a routine promotion. Legitimate possible causes: ${tg003Rule.legitimate_causes}`,
      });
    }
  });

  // =========================================================================
  // RULE TG004: Outbound transfer >= 10 MiB to public IP OR port 4444/1337
  // Exclude private, loopback, link-local, multicast and documentation IP ranges (IPv4 & IPv6).
  // Explain heuristic and legitimate causes; never claim proven exfiltration or C2.
  // =========================================================================
  const tg004Rule = RULE_DEFINITIONS.TG004;

  sortedEvents.forEach((evt) => {
    const destPort = evt.destination_port;
    const destIp = evt.destination_ip;
    const bytesTransferred = evt.bytes || 0;

    const isSuspiciousPort = destPort !== undefined && TG004_SUSPICIOUS_PORTS.includes(destPort);
    const isPublic = destIp ? isPublicIp(destIp) : false;
    const isLargeEgress = bytesTransferred >= TG004_EGRESS_THRESHOLD_BYTES && isPublic;

    if (isLargeEgress || isSuspiciousPort) {
      let specificReason = '';
      if (isLargeEgress && isSuspiciousPort) {
        const mb = (bytesTransferred / (1024 * 1024)).toFixed(2);
        specificReason = `Outbound transfer of ${mb} MiB to public IP (${destIp}) over high-risk port ${destPort}.`;
      } else if (isLargeEgress) {
        const mb = (bytesTransferred / (1024 * 1024)).toFixed(2);
        specificReason = `Outbound data transfer of ${mb} MiB (>= 10 MiB threshold) to non-reserved public IP address ${destIp}.`;
      } else {
        specificReason = `Outbound connection attempt directed to high-risk port ${destPort} (${destPort === 4444 ? 'default Metasploit listener' : 'unauthorized service/leet port'}). Destination IP: ${destIp || 'Unspecified'}.`;
      }

      findings.push({
        id: `FND-TG004-${findingCounter++}`,
        rule_id: 'TG004',
        rule_title: tg004Rule.name,
        category: tg004Rule.category,
        severity: tg004Rule.severity,
        summary: `Suspicious network egress detected: ${specificReason}`,
        explanation: `${specificReason} Private, loopback, multicast, link-local, and documentation subnets (RFC 1918, RFC 5737, IPv6 ULA/Doc) were validated and excluded. This heuristic flags anomalies for investigation.`,
        entity_source_ip: evt.source_ip,
        entity_user: evt.user,
        trigger_event_ids: [evt.id],
        first_seen_utc: evt.timestamp,
        last_seen_utc: evt.timestamp,
        supporting_events: [evt],
        suggested_investigation_steps: tg004Rule.investigation_steps,
        caveat_notice: `Important: This finding is an automated heuristic and does NOT prove exfiltration or command-and-control. Legitimate causes: ${tg004Rule.legitimate_causes}`,
      });
    }
  });

  // =========================================================================
  // RULE TG005: Potential secrets in log fields
  // Redacted matched values across all displayed and exported fields.
  // =========================================================================
  const tg005Rule = RULE_DEFINITIONS.TG005;

  sortedEvents.forEach((evt) => {
    if (evt.has_redacted_secret) {
      findings.push({
        id: `FND-TG005-${findingCounter++}`,
        rule_id: 'TG005',
        rule_title: tg005Rule.name,
        category: tg005Rule.category,
        severity: tg005Rule.severity,
        summary: `Sensitive secret pattern identified and redacted in event "${evt.event_type}" payload.`,
        explanation: `One or more secret patterns (such as AWS access key identifiers, private key markers, bearer tokens, or password parameters) were discovered in event fields. TraceGuard has automatically masked all instances with redaction tokens before display and export.`,
        entity_source_ip: evt.source_ip,
        entity_user: evt.user,
        trigger_event_ids: [evt.id],
        first_seen_utc: evt.timestamp,
        last_seen_utc: evt.timestamp,
        supporting_events: [evt],
        suggested_investigation_steps: tg005Rule.investigation_steps,
        caveat_notice: `Security notice: Pattern matching is best-effort. Verify secret exposure in upstream logging services and rotate exposed credentials immediately. Legitimate causes: ${tg005Rule.legitimate_causes}`,
      });
    }
  });

  // Sort findings by severity priority (critical > high > medium > low), then chronologically
  const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => {
    const diff = severityRank[b.severity] - severityRank[a.severity];
    if (diff !== 0) return diff;
    return Date.parse(b.last_seen_utc) - Date.parse(a.last_seen_utc);
  });

  return findings;
}
