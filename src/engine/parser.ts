import { isValidIp } from './ipUtils';
import { sanitizeLogValue, sanitizeText } from './redaction';
import { RejectedRow, SecurityLogEvent, ValidationSummary } from './types';

export const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2 MiB
export const MAX_EVENT_COUNT = 20000;

// Supported field aliases mapping to canonical properties
export const FIELD_ALIASES: Record<string, string[]> = {
  timestamp: ['timestamp', 'time', 'datetime', '@timestamp', 'event_time', 'date'],
  event_type: ['event_type', 'action', 'type', 'event', 'activity', 'operation', 'event_name'],
  user: ['user', 'username', 'account', 'user_name', 'principal', 'subject'],
  source_ip: ['source_ip', 'src_ip', 'client_ip', 'source_address', 'src_addr', 'ip', 'clientip'],
  destination_ip: ['destination_ip', 'dest_ip', 'dst_ip', 'server_ip', 'remote_ip', 'dst_addr'],
  destination_port: ['destination_port', 'dest_port', 'dst_port', 'port', 'remote_port', 'dstport'],
  bytes: ['bytes', 'size', 'bytes_sent', 'bytes_transferred', 'bytes_out', 'payload_size', 'length'],
  status: ['status', 'result', 'outcome', 'action_status', 'state'],
  new_role: ['new_role', 'role', 'assigned_role', 'target_role', 'granted_role', 'newrole'],
  message: ['message', 'msg', 'description', 'details', 'log_message', 'summary'],
};

/**
 * Validates ISO 8601 timestamp string strictly by parsing and validating
 * each calendar date, time, and timezone offset component.
 * Rejects impossible dates like 2026-02-30 or 2026-04-31 without silent rollover.
 */
export function validateIso8601Timestamp(timestampStr: string): {
  valid: boolean;
  epochMs?: number;
  normalizedUtc?: string;
  error?: string;
} {
  const trimmed = timestampStr.trim();
  const match = trimmed.match(
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})$/i
  );

  if (!match) {
    return {
      valid: false,
      error: `Invalid timestamp format "${sanitizeText(trimmed)}". Must be ISO 8601 with explicit timezone (e.g. "2026-10-07T12:00:00Z" or "+00:00").`,
    };
  }

  const year = parseInt(match[1], 10);
  const month = parseInt(match[2], 10);
  const day = parseInt(match[3], 10);
  const hour = parseInt(match[4], 10);
  const minute = parseInt(match[5], 10);
  const second = parseInt(match[6], 10);
  const fractionStr = match[7] || '';
  const tzStr = match[8];

  if (year < 1000 || year > 9999) {
    return { valid: false, error: `Invalid year "${year}" in timestamp.` };
  }

  if (month < 1 || month > 12) {
    return { valid: false, error: `Invalid month "${month}" in timestamp (must be 01 to 12).` };
  }

  // Days in month validation with leap year calculation
  const isLeapYear = (year % 4 === 0 && year % 100 !== 0) || (year % 400 === 0);
  let maxDays = 31;
  if (month === 2) {
    maxDays = isLeapYear ? 29 : 28;
  } else if (month === 4 || month === 6 || month === 9 || month === 11) {
    maxDays = 30;
  }

  if (day < 1 || day > maxDays) {
    const monthNames = [
      'January', 'February', 'March', 'April', 'May', 'June',
      'July', 'August', 'September', 'October', 'November', 'December'
    ];
    return {
      valid: false,
      error: `Calendar day ${day} is invalid for ${monthNames[month - 1]} in year ${year} (max ${maxDays} days).`,
    };
  }

  if (hour < 0 || hour > 23) {
    return { valid: false, error: `Hour ${hour} is invalid in timestamp (must be 00 to 23).` };
  }

  if (minute < 0 || minute > 59) {
    return { valid: false, error: `Minute ${minute} is invalid in timestamp (must be 00 to 59).` };
  }

  if (second < 0 || second > 59) {
    return { valid: false, error: `Second ${second} is invalid in timestamp (must be 00 to 59).` };
  }

  // Timezone offset validation
  let offsetMinutes = 0;
  if (tzStr.toUpperCase() !== 'Z') {
    const tzMatch = tzStr.match(/^([+-])(\d{2}):?(\d{2})$/);
    if (!tzMatch) {
      return { valid: false, error: `Invalid timezone offset format "${sanitizeText(tzStr)}".` };
    }
    const sign = tzMatch[1] === '-' ? -1 : 1;
    const tzH = parseInt(tzMatch[2], 10);
    const tzM = parseInt(tzMatch[3], 10);

    if (tzH < 0 || tzH > 14 || tzM < 0 || tzM > 59) {
      return {
        valid: false,
        error: `Timezone offset hours must be 00..14 and minutes 00..59 (got "${sanitizeText(tzStr)}").`,
      };
    }
    offsetMinutes = sign * (tzH * 60 + tzM);
  }

  // Calculate UTC epoch milliseconds
  const ms = fractionStr ? parseInt(fractionStr.padEnd(3, '0').slice(0, 3), 10) : 0;
  const utcBaseMs = Date.UTC(year, month - 1, day, hour, minute, second, ms);
  const epochMs = utcBaseMs - (offsetMinutes * 60 * 1000);

  if (!Number.isFinite(epochMs)) {
    return { valid: false, error: 'Unparseable date value.' };
  }

  const normalizedUtc = new Date(epochMs).toISOString();
  return { valid: true, epochMs, normalizedUtc };
}

/**
 * Strict RFC 4180 CSV parser enforcing state validation:
 * - Detects and rejects unterminated quotes at EOF
 * - Rejects unquoted fields that contain quote characters
 * - Rejects trailing characters after closing quotes
 * - Accurately supports quoted multiline fields
 */
export function parseCsvRecords(text: string): { records: string[][]; error?: string } {
  const records: string[][] = [];
  let currentRecord: string[] = [];
  let currentField = '';
  let inQuotes = false;
  let fieldStartedWithQuote = false;
  let quoteJustClosed = false;
  let currentLineNumber = 1;

  let i = 0;
  const len = text.length;

  while (i < len) {
    const char = text[i];
    const nextChar = text[i + 1];

    if (inQuotes) {
      if (char === '"') {
        if (nextChar === '"') {
          // Escaped double quote inside quoted field
          currentField += '"';
          i += 2;
          continue;
        } else {
          // Closing quote of quoted field
          inQuotes = false;
          quoteJustClosed = true;
          i++;
          continue;
        }
      } else {
        if (char === '\n') {
          currentLineNumber++;
        }
        currentField += char;
        i++;
        continue;
      }
    } else {
      // Not currently inside quotes
      if (quoteJustClosed) {
        // Must immediately be followed by delimiter (comma), newline, or EOF
        if (char === ',') {
          currentRecord.push(currentField);
          currentField = '';
          fieldStartedWithQuote = false;
          quoteJustClosed = false;
          i++;
          continue;
        } else if (char === '\r') {
          if (nextChar === '\n') {
            i += 2;
          } else {
            i++;
          }
          currentRecord.push(currentField);
          records.push(currentRecord);
          currentRecord = [];
          currentField = '';
          fieldStartedWithQuote = false;
          quoteJustClosed = false;
          currentLineNumber++;
          continue;
        } else if (char === '\n') {
          currentRecord.push(currentField);
          records.push(currentRecord);
          currentRecord = [];
          currentField = '';
          fieldStartedWithQuote = false;
          quoteJustClosed = false;
          currentLineNumber++;
          i++;
          continue;
        } else {
          // Trailing characters after closing quote
          return {
            records: [],
            error: `Trailing characters found after closing quote at line ${currentLineNumber}.`,
          };
        }
      }

      // Starting a new field or continuing unquoted field
      if (currentField.length === 0 && !fieldStartedWithQuote) {
        if (char === '"') {
          inQuotes = true;
          fieldStartedWithQuote = true;
          i++;
          continue;
        }
      }

      if (char === '"') {
        // Quote character inside an unquoted field
        return {
          records: [],
          error: `Unexpected quote character inside unquoted field at line ${currentLineNumber}.`,
        };
      } else if (char === ',') {
        currentRecord.push(currentField);
        currentField = '';
        fieldStartedWithQuote = false;
        quoteJustClosed = false;
        i++;
        continue;
      } else if (char === '\r') {
        if (nextChar === '\n') {
          i += 2;
        } else {
          i++;
        }
        currentRecord.push(currentField);
        records.push(currentRecord);
        currentRecord = [];
        currentField = '';
        fieldStartedWithQuote = false;
        quoteJustClosed = false;
        currentLineNumber++;
        continue;
      } else if (char === '\n') {
        currentRecord.push(currentField);
        records.push(currentRecord);
        currentRecord = [];
        currentField = '';
        fieldStartedWithQuote = false;
        quoteJustClosed = false;
        currentLineNumber++;
        i++;
        continue;
      } else {
        currentField += char;
        i++;
        continue;
      }
    }
  }

  // End of file checks
  if (inQuotes) {
    return {
      records: [],
      error: `Unterminated quote in CSV record at line ${currentLineNumber}.`,
    };
  }

  if (currentField.length > 0 || fieldStartedWithQuote || quoteJustClosed || currentRecord.length > 0) {
    currentRecord.push(currentField);
    records.push(currentRecord);
  }

  // Filter out any purely empty trailing record
  const filtered = records.filter(
    (r) => r.length > 1 || (r.length === 1 && r[0].trim() !== '')
  );

  return { records: filtered };
}

/**
 * Resolve canonical field name using alias definitions.
 */
function resolveCanonicalKey(rawKey: string): string | null {
  const normalized = rawKey.trim().toLowerCase().replace(/[-_]/g, '_');
  for (const [canonical, aliases] of Object.entries(FIELD_ALIASES)) {
    if (canonical === normalized) return canonical;
    if (aliases.some((alias) => alias.replace(/[-_]/g, '_') === normalized)) {
      return canonical;
    }
  }
  return null;
}

/**
 * Validate and normalize a single log event object.
 * Returns either normalized SecurityLogEvent or error string.
 */
export function validateAndNormalizeEvent(
  rawObj: Record<string, unknown>,
  idFallback: string,
  lineNumber?: number
): { event?: SecurityLogEvent; error?: string } {
  if (typeof rawObj !== 'object' || rawObj === null || Array.isArray(rawObj)) {
    return { error: 'Row is not a structured key-value map.' };
  }

  const normalizedMap: Record<string, unknown> = {};
  const unmappedRaw: Record<string, unknown> = {};

  for (const [key, val] of Object.entries(rawObj)) {
    const canonical = resolveCanonicalKey(key);
    if (canonical) {
      if (normalizedMap[canonical] === undefined) {
        normalizedMap[canonical] = val;
      }
    } else {
      unmappedRaw[key] = val;
    }
  }

  // 1. Mandatory event_type
  const rawEventType = normalizedMap['event_type'];
  if (!rawEventType || typeof rawEventType !== 'string' || rawEventType.trim() === '') {
    return { error: "Missing required 'event_type' field." };
  }
  const event_type = rawEventType.trim();

  // 2. Mandatory timestamp with ISO 8601 & explicit calendar date validation
  const rawTimestamp = normalizedMap['timestamp'];
  if (!rawTimestamp || typeof rawTimestamp !== 'string' || rawTimestamp.trim() === '') {
    return { error: "Missing required 'timestamp' field." };
  }

  const dateValidation = validateIso8601Timestamp(rawTimestamp);
  if (!dateValidation.valid || !dateValidation.epochMs || !dateValidation.normalizedUtc) {
    return {
      error: dateValidation.error || 'Invalid timestamp format.',
    };
  }

  const normalizedIsoTimestamp = dateValidation.normalizedUtc;
  const epochMs = dateValidation.epochMs;

  // 3. Source IP validation (optional)
  let source_ip: string | undefined;
  if (
    normalizedMap['source_ip'] !== undefined &&
    normalizedMap['source_ip'] !== null &&
    String(normalizedMap['source_ip']).trim() !== ''
  ) {
    const ipStr = String(normalizedMap['source_ip']).trim();
    if (!isValidIp(ipStr)) {
      return {
        error: `Invalid source IP address format: "${sanitizeText(ipStr)}". Must be valid IPv4 or IPv6.`,
      };
    }
    source_ip = ipStr;
  }

  // 4. Destination IP validation (optional)
  let destination_ip: string | undefined;
  if (
    normalizedMap['destination_ip'] !== undefined &&
    normalizedMap['destination_ip'] !== null &&
    String(normalizedMap['destination_ip']).trim() !== ''
  ) {
    const ipStr = String(normalizedMap['destination_ip']).trim();
    if (!isValidIp(ipStr)) {
      return {
        error: `Invalid destination IP address format: "${sanitizeText(ipStr)}". Must be valid IPv4 or IPv6.`,
      };
    }
    destination_ip = ipStr;
  }

  // 5. Destination Port validation (optional, strict finite integer 1..65535)
  let destination_port: number | undefined;
  if (
    normalizedMap['destination_port'] !== undefined &&
    normalizedMap['destination_port'] !== null &&
    String(normalizedMap['destination_port']).trim() !== ''
  ) {
    const rawPort = normalizedMap['destination_port'];
    if (typeof rawPort === 'boolean' || Array.isArray(rawPort) || (typeof rawPort === 'object' && rawPort !== null)) {
      return {
        error: `Destination port cannot be a boolean, array, or object (got ${sanitizeText(JSON.stringify(rawPort))}).`,
      };
    }
    if (typeof rawPort === 'number') {
      if (!Number.isFinite(rawPort) || !Number.isSafeInteger(rawPort) || rawPort < 1 || rawPort > 65535) {
        return {
          error: `Destination port must be an integer between 1 and 65535 (got ${sanitizeText(String(rawPort))}).`,
        };
      }
      destination_port = rawPort;
    } else {
      const strPort = String(rawPort).trim();
      if (!/^\d+$/.test(strPort)) {
        return {
          error: `Destination port must be an integer between 1 and 65535 (got ${sanitizeText(strPort)}).`,
        };
      }
      const portNum = Number(strPort);
      if (!Number.isSafeInteger(portNum) || portNum < 1 || portNum > 65535) {
        return {
          error: `Destination port must be an integer between 1 and 65535 (got ${sanitizeText(strPort)}).`,
        };
      }
      destination_port = portNum;
    }
  }

  // 6. Bytes validation (optional, strict finite non-negative safe integer >= 0)
  let bytes: number | undefined;
  if (
    normalizedMap['bytes'] !== undefined &&
    normalizedMap['bytes'] !== null &&
    String(normalizedMap['bytes']).trim() !== ''
  ) {
    const rawBytes = normalizedMap['bytes'];
    if (typeof rawBytes === 'boolean' || Array.isArray(rawBytes) || (typeof rawBytes === 'object' && rawBytes !== null)) {
      return {
        error: `Bytes transferred cannot be a boolean, array, or object (got ${sanitizeText(JSON.stringify(rawBytes))}).`,
      };
    }
    if (typeof rawBytes === 'number') {
      if (!Number.isFinite(rawBytes) || !Number.isSafeInteger(rawBytes) || rawBytes < 0) {
        return {
          error: `Bytes transferred must be a finite non-negative integer without fractions (got ${sanitizeText(String(rawBytes))}).`,
        };
      }
      bytes = rawBytes;
    } else {
      const strBytes = String(rawBytes).trim();
      if (!/^\d+$/.test(strBytes)) {
        return {
          error: `Bytes transferred must be a finite non-negative integer without fractions (got ${sanitizeText(strBytes)}).`,
        };
      }
      const bytesNum = Number(strBytes);
      if (!Number.isSafeInteger(bytesNum) || bytesNum < 0) {
        return {
          error: `Bytes transferred must be a safe non-negative integer (got ${sanitizeText(strBytes)}).`,
        };
      }
      bytes = bytesNum;
    }
  }

  // Optional string fields
  const user =
    normalizedMap['user'] !== undefined && normalizedMap['user'] !== null
      ? String(normalizedMap['user']).trim()
      : undefined;
  const status =
    normalizedMap['status'] !== undefined && normalizedMap['status'] !== null
      ? String(normalizedMap['status']).trim().toLowerCase()
      : undefined;
  const new_role =
    normalizedMap['new_role'] !== undefined && normalizedMap['new_role'] !== null
      ? String(normalizedMap['new_role']).trim()
      : undefined;
  const message =
    normalizedMap['message'] !== undefined && normalizedMap['message'] !== null
      ? String(normalizedMap['message']).trim()
      : undefined;

  // Sanitize all values for potential secrets (TG005)
  const fullLogToSanitize: Record<string, unknown> = {
    ...rawObj,
    event_type,
    user,
    source_ip,
    destination_ip,
    destination_port,
    bytes,
    status,
    new_role,
    message,
  };

  const sanitizeResult = sanitizeLogValue(fullLogToSanitize);
  const sanitizedRecord = sanitizeResult.sanitized as Record<string, unknown>;
  const hasSecrets = sanitizeResult.foundTypes.length > 0;

  const event: SecurityLogEvent = {
    id: idFallback,
    line_number: lineNumber,
    timestamp: normalizedIsoTimestamp,
    timestamp_epoch: epochMs,
    event_type: String(sanitizedRecord.event_type || event_type),
    user: sanitizedRecord.user !== undefined ? String(sanitizedRecord.user) : undefined,
    source_ip: sanitizedRecord.source_ip !== undefined ? String(sanitizedRecord.source_ip) : undefined,
    destination_ip: sanitizedRecord.destination_ip !== undefined ? String(sanitizedRecord.destination_ip) : undefined,
    destination_port,
    bytes,
    status: sanitizedRecord.status !== undefined ? String(sanitizedRecord.status) : undefined,
    new_role: sanitizedRecord.new_role !== undefined ? String(sanitizedRecord.new_role) : undefined,
    message: sanitizedRecord.message !== undefined ? String(sanitizedRecord.message) : undefined,
    raw: sanitizedRecord,
    has_redacted_secret: hasSecrets,
  };

  return { event };
}

/**
 * Main parse function supporting JSON (array or {events:[...]}) and CSV.
 */
export function parseSecurityLogs(
  fileContent: string,
  fileName: string,
  fileSizeBytes: number
): {
  success: boolean;
  events: SecurityLogEvent[];
  validation: ValidationSummary;
  fatalError?: string;
} {
  const analysisTimestampUtc = new Date().toISOString();
  const safeFileName = sanitizeText(fileName);

  // Size limit check: 2 MiB
  if (fileSizeBytes > MAX_FILE_SIZE_BYTES) {
    const actualMb = (fileSizeBytes / (1024 * 1024)).toFixed(2);
    return {
      success: false,
      events: [],
      validation: {
        file_name: safeFileName,
        file_size_bytes: fileSizeBytes,
        total_rows: 0,
        valid_count: 0,
        rejected_count: 0,
        rejected_rows: [],
        analysis_timestamp_utc: analysisTimestampUtc,
      },
      fatalError: `File size exceeds the 2 MiB safety limit (${actualMb} MiB). Please upload a smaller log sample.`,
    };
  }

  const trimmed = fileContent.trim();
  if (!trimmed) {
    return {
      success: false,
      events: [],
      validation: {
        file_name: safeFileName,
        file_size_bytes: fileSizeBytes,
        total_rows: 0,
        valid_count: 0,
        rejected_count: 0,
        rejected_rows: [],
        analysis_timestamp_utc: analysisTimestampUtc,
      },
      fatalError: 'The provided log file is completely empty.',
    };
  }

  const validEvents: SecurityLogEvent[] = [];
  const rejectedRows: RejectedRow[] = [];
  let totalRowsCount = 0;

  const isJson = trimmed.startsWith('{') || trimmed.startsWith('[');

  if (isJson) {
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(trimmed);
    } catch (err: unknown) {
      const rawErrMsg = err instanceof Error ? err.message : String(err);
      // Ensure any input excerpts echoed in the JSON parser error are sanitized
      const safeErrMsg = sanitizeText(rawErrMsg);
      return {
        success: false,
        events: [],
        validation: {
          file_name: safeFileName,
          file_size_bytes: fileSizeBytes,
          total_rows: 0,
          valid_count: 0,
          rejected_count: 0,
          rejected_rows: [],
          analysis_timestamp_utc: analysisTimestampUtc,
        },
        fatalError: `Malformed JSON file syntax: ${safeErrMsg}. Please ensure valid JSON formatting.`,
      };
    }

    let items: unknown[] = [];
    if (Array.isArray(parsedJson)) {
      items = parsedJson;
    } else if (
      parsedJson &&
      typeof parsedJson === 'object' &&
      Array.isArray((parsedJson as Record<string, unknown>).events)
    ) {
      items = (parsedJson as Record<string, unknown>).events as unknown[];
    } else {
      return {
        success: false,
        events: [],
        validation: {
          file_name: safeFileName,
          file_size_bytes: fileSizeBytes,
          total_rows: 0,
          valid_count: 0,
          rejected_count: 0,
          rejected_rows: [],
          analysis_timestamp_utc: analysisTimestampUtc,
        },
        fatalError: 'JSON structure must be an array of event objects or an object containing an "events" array.',
      };
    }

    if (items.length > MAX_EVENT_COUNT) {
      return {
        success: false,
        events: [],
        validation: {
          file_name: safeFileName,
          file_size_bytes: fileSizeBytes,
          total_rows: items.length,
          valid_count: 0,
          rejected_count: 0,
          rejected_rows: [],
          analysis_timestamp_utc: analysisTimestampUtc,
        },
        fatalError: `Log contains ${items.length.toLocaleString()} events, exceeding the 20,000 events limit.`,
      };
    }

    totalRowsCount = items.length;

    items.forEach((item, index) => {
      const rowNum = index + 1;
      let sanitizedRaw = '';
      if (typeof item === 'object' && item !== null) {
        const sanitizedObj = sanitizeLogValue(item).sanitized;
        sanitizedRaw = sanitizeText(JSON.stringify(sanitizedObj));
      } else {
        sanitizedRaw = sanitizeText(String(item));
      }
      // Sanitize raw content preview BEFORE truncating to avoid splitting tokens
      const truncatedRaw = sanitizedRaw.slice(0, 160);

      if (typeof item !== 'object' || item === null) {
        rejectedRows.push({
          row_number: rowNum,
          raw_content: truncatedRaw,
          error: 'Event item must be a JSON object.',
        });
        return;
      }

      const res = validateAndNormalizeEvent(item as Record<string, unknown>, `evt-${rowNum}`, rowNum);
      if (res.event) {
        validEvents.push(res.event);
      } else {
        rejectedRows.push({
          row_number: rowNum,
          raw_content: truncatedRaw,
          error: sanitizeText(res.error || 'Failed validation check.'),
        });
      }
    });
  } else {
    // Strict CSV Parsing
    const csvResult = parseCsvRecords(trimmed);
    if (csvResult.error) {
      const safeCsvError = sanitizeText(csvResult.error);
      return {
        success: false,
        events: [],
        validation: {
          file_name: safeFileName,
          file_size_bytes: fileSizeBytes,
          total_rows: 0,
          valid_count: 0,
          rejected_count: 0,
          rejected_rows: [],
          analysis_timestamp_utc: analysisTimestampUtc,
        },
        fatalError: `Malformed CSV structure: ${safeCsvError}`,
      };
    }

    const csvRecords = csvResult.records;

    if (csvRecords.length < 2) {
      return {
        success: false,
        events: [],
        validation: {
          file_name: safeFileName,
          file_size_bytes: fileSizeBytes,
          total_rows: csvRecords.length,
          valid_count: 0,
          rejected_count: 0,
          rejected_rows: [],
          analysis_timestamp_utc: analysisTimestampUtc,
        },
        fatalError: 'CSV file must contain a header row and at least one data row.',
      };
    }

    const headers = csvRecords[0].map((h) => h.trim());

    // Check duplicate headers
    const seenHeaders = new Set<string>();
    for (const h of headers) {
      const lower = h.toLowerCase();
      if (seenHeaders.has(lower)) {
        return {
          success: false,
          events: [],
          validation: {
            file_name: safeFileName,
            file_size_bytes: fileSizeBytes,
            total_rows: 0,
            valid_count: 0,
            rejected_count: 0,
            rejected_rows: [],
            analysis_timestamp_utc: analysisTimestampUtc,
          },
          fatalError: `Duplicate column header "${sanitizeText(h)}" detected in CSV. Headers must be unique.`,
        };
      }
      seenHeaders.add(lower);
    }

    const dataRows = csvRecords.slice(1);
    totalRowsCount = dataRows.length;

    if (totalRowsCount > MAX_EVENT_COUNT) {
      return {
        success: false,
        events: [],
        validation: {
          file_name: safeFileName,
          file_size_bytes: fileSizeBytes,
          total_rows: totalRowsCount,
          valid_count: 0,
          rejected_count: 0,
          rejected_rows: [],
          analysis_timestamp_utc: analysisTimestampUtc,
        },
        fatalError: `CSV contains ${totalRowsCount.toLocaleString()} events, exceeding the 20,000 events limit.`,
      };
    }

    const expectedColCount = headers.length;

    dataRows.forEach((row, idx) => {
      const lineNum = idx + 2; // header is line 1
      
      // Sanitize each cell before previewing, masking sensitive column headers explicitly
      const sanitizedCells = row.map((cell, colIdx) => {
        const header = headers[colIdx] ? headers[colIdx].toLowerCase() : '';
        if (/^(password|passwd|pwd|secret|secret_key|api_key|client_secret|access_token|auth_token|token|private_key)$/i.test(header)) {
          return '[REDACTED_SECRET:PASSWORD]';
        }
        return sanitizeText(cell);
      });
      const sanitizedRawPreview = sanitizeText(sanitizedCells.join(',')).slice(0, 160);

      // Check column count consistency
      if (row.length !== expectedColCount) {
        rejectedRows.push({
          row_number: lineNum,
          raw_content: sanitizedRawPreview,
          error: `Row has ${row.length} columns, expected ${expectedColCount} columns matching header.`,
        });
        return;
      }

      // Create object from row
      const rowObj: Record<string, unknown> = {};
      headers.forEach((header, colIdx) => {
        if (header) {
          rowObj[header] = row[colIdx] !== undefined ? row[colIdx] : '';
        }
      });

      const res = validateAndNormalizeEvent(rowObj, `evt-${idx + 1}`, lineNum);
      if (res.event) {
        validEvents.push(res.event);
      } else {
        rejectedRows.push({
          row_number: lineNum,
          raw_content: sanitizedRawPreview,
          error: sanitizeText(res.error || 'Failed row validation.'),
        });
      }
    });
  }

  // Check if ALL rows were invalid
  if (totalRowsCount > 0 && validEvents.length === 0) {
    return {
      success: false,
      events: [],
      validation: {
        file_name: safeFileName,
        file_size_bytes: fileSizeBytes,
        total_rows: totalRowsCount,
        valid_count: 0,
        rejected_count: rejectedRows.length,
        rejected_rows: rejectedRows,
        analysis_timestamp_utc: analysisTimestampUtc,
      },
      fatalError: `All ${totalRowsCount} rows failed schema validation. Please check field names ('event_type', 'timestamp' with timezone) and review the schema documentation.`,
    };
  }

  // Sort valid events ascending by timestamp_epoch
  validEvents.sort((a, b) => a.timestamp_epoch - b.timestamp_epoch);

  const earliestUtc = validEvents.length > 0 ? validEvents[0].timestamp : undefined;
  const latestUtc = validEvents.length > 0 ? validEvents[validEvents.length - 1].timestamp : undefined;

  const validation: ValidationSummary = {
    file_name: safeFileName,
    file_size_bytes: fileSizeBytes,
    total_rows: totalRowsCount,
    valid_count: validEvents.length,
    rejected_count: rejectedRows.length,
    rejected_rows: rejectedRows,
    earliest_event_utc: earliestUtc,
    latest_event_utc: latestUtc,
    analysis_timestamp_utc: analysisTimestampUtc,
  };

  return {
    success: true,
    events: validEvents,
    validation,
  };
}