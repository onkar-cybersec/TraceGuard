/**
 * Redaction utility for detecting and scrubbing potential secrets in security logs (TG005).
 * Enforces best-effort defense-in-depth sanitization across all display and export surfaces.
 */

export interface RedactionResult {
  sanitized: string;
  foundTypes: string[];
}

export const SECRET_PATTERNS = {
  PRIVATE_KEY_BLOCK: /-----BEGIN [A-Z0-9\s_-]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9\s_-]*PRIVATE KEY-----/gi,
  PRIVATE_KEY_HEADER: /-----BEGIN [A-Z0-9\s_-]*PRIVATE KEY[^\n\r-]*/gi,
  AWS_ACCESS_KEY: /(?:^|[^A-Za-z0-9])((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})(?![0-9A-Z])/g,
  BEARER_AUTH_HEADER: /\bBearer\s+[A-Za-z0-9_.\-+/=]{20,}\b/gi,
  JWT_COMPACT: /\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g,
  PASSWORD_ASSIGNMENT: /(?:["']?\b(?:password|passwd|pwd|secret|secret_key|api_key|client_secret|access_token|auth_token|token|private_key)\b["']?\s*[:=]\s*)(?:(?:"([^"\r\n]*)")|(?:'([^'\r\n]*)')|([^\s,;"'}{]+))/gi,
};

/**
 * Universal string sanitizer that scrubs all recognized secret patterns.
 */
export function sanitizeText(input: unknown): string {
  if (input === null || input === undefined) return '';
  const s = typeof input === 'string' ? input : String(input);
  return redactSecretsInString(s).sanitized;
}

/**
 * Redact potential secrets in a raw string.
 * Replaces recognized secret shapes with explicit redaction tags.
 */
export function redactSecretsInString(input: string): RedactionResult {
  if (!input || typeof input !== 'string') {
    return { sanitized: input, foundTypes: [] };
  }

  const foundTypes = new Set<string>();
  let sanitized = input;

  // 1. Full private key block or header
  SECRET_PATTERNS.PRIVATE_KEY_BLOCK.lastIndex = 0;
  if (SECRET_PATTERNS.PRIVATE_KEY_BLOCK.test(sanitized)) {
    foundTypes.add('Private Key Block');
    SECRET_PATTERNS.PRIVATE_KEY_BLOCK.lastIndex = 0;
    sanitized = sanitized.replace(SECRET_PATTERNS.PRIVATE_KEY_BLOCK, '[REDACTED_SECRET:PRIVATE_KEY_BLOCK]');
  }
  SECRET_PATTERNS.PRIVATE_KEY_HEADER.lastIndex = 0;
  if (SECRET_PATTERNS.PRIVATE_KEY_HEADER.test(sanitized)) {
    foundTypes.add('Private Key Header');
    SECRET_PATTERNS.PRIVATE_KEY_HEADER.lastIndex = 0;
    sanitized = sanitized.replace(SECRET_PATTERNS.PRIVATE_KEY_HEADER, '[REDACTED_SECRET:PRIVATE_KEY_HEADER]');
  }

  // 2. AWS Access Key identifiers (AKIA..., ASIA...)
  SECRET_PATTERNS.AWS_ACCESS_KEY.lastIndex = 0;
  if (SECRET_PATTERNS.AWS_ACCESS_KEY.test(sanitized)) {
    foundTypes.add('AWS Access Key Identifier');
    SECRET_PATTERNS.AWS_ACCESS_KEY.lastIndex = 0;
    sanitized = sanitized.replace(SECRET_PATTERNS.AWS_ACCESS_KEY, (match, key: string) => {
      const prefixChar = match.length > key.length ? match[0] : '';
      const prefix = key.slice(0, 4);
      return `${prefixChar}[REDACTED_SECRET:${prefix}_KEY]`;
    });
  }

  // 3. Bearer token headers
  SECRET_PATTERNS.BEARER_AUTH_HEADER.lastIndex = 0;
  if (SECRET_PATTERNS.BEARER_AUTH_HEADER.test(sanitized)) {
    foundTypes.add('Bearer Token');
    SECRET_PATTERNS.BEARER_AUTH_HEADER.lastIndex = 0;
    sanitized = sanitized.replace(SECRET_PATTERNS.BEARER_AUTH_HEADER, 'Bearer [REDACTED_SECRET:BEARER_TOKEN]');
  }

  // 4. Compact JWT tokens
  SECRET_PATTERNS.JWT_COMPACT.lastIndex = 0;
  if (SECRET_PATTERNS.JWT_COMPACT.test(sanitized)) {
    foundTypes.add('JWT Token');
    SECRET_PATTERNS.JWT_COMPACT.lastIndex = 0;
    sanitized = sanitized.replace(SECRET_PATTERNS.JWT_COMPACT, '[REDACTED_SECRET:JWT_TOKEN]');
  }

  // 5. Password assignments in strings (e.g. password=Secret123! or "password": "Secret123!")
  SECRET_PATTERNS.PASSWORD_ASSIGNMENT.lastIndex = 0;
  if (SECRET_PATTERNS.PASSWORD_ASSIGNMENT.test(sanitized)) {
    foundTypes.add('Password / Credential Assignment');
    SECRET_PATTERNS.PASSWORD_ASSIGNMENT.lastIndex = 0;
    sanitized = sanitized.replace(SECRET_PATTERNS.PASSWORD_ASSIGNMENT, (match) => {
      const colonIdx = match.indexOf(':');
      const eqIdx = match.indexOf('=');
      const sepIdx =
        colonIdx !== -1 && eqIdx !== -1
          ? Math.min(colonIdx, eqIdx)
          : colonIdx !== -1
          ? colonIdx
          : eqIdx;
      if (sepIdx !== -1) {
        const keyPart = match.slice(0, sepIdx + 1);
        return `${keyPart} [REDACTED_SECRET:PASSWORD]`;
      }
      return '[REDACTED_SECRET:PASSWORD]';
    });
  }

  return { sanitized, foundTypes: Array.from(foundTypes) };
}

/**
 * Deep-traverse and sanitize arbitrary object/array structures,
 * catching secrets in nested values or sensitive keys.
 */
export function sanitizeLogValue(val: unknown): { sanitized: unknown; foundTypes: string[] } {
  if (val === null || val === undefined) {
    return { sanitized: val, foundTypes: [] };
  }

  if (typeof val === 'string') {
    const { sanitized, foundTypes } = redactSecretsInString(val);
    return { sanitized, foundTypes };
  }

  if (Array.isArray(val)) {
    const allTypes = new Set<string>();
    const sanitizedArray = val.map((item) => {
      const res = sanitizeLogValue(item);
      res.foundTypes.forEach((t) => allTypes.add(t));
      return res.sanitized;
    });
    return { sanitized: sanitizedArray, foundTypes: Array.from(allTypes) };
  }

  if (typeof val === 'object') {
    const allTypes = new Set<string>();
    const sanitizedObj: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(val as Record<string, unknown>)) {
      // Sensitive key name check (e.g. key is 'password', 'client_secret', 'auth_token', 'token')
      const lowerKey = key.toLowerCase();
      if (
        /^(password|passwd|pwd|secret|secret_key|api_key|client_secret|access_token|auth_token|token|private_key)$/.test(lowerKey) &&
        typeof value === 'string'
      ) {
        allTypes.add(`Sensitive Field: ${key}`);
        sanitizedObj[key] = `[REDACTED_SECRET:${key.toUpperCase()}]`;
        continue;
      }

      const res = sanitizeLogValue(value);
      res.foundTypes.forEach((t) => allTypes.add(t));
      sanitizedObj[key] = res.sanitized;
    }

    return { sanitized: sanitizedObj, foundTypes: Array.from(allTypes) };
  }

  return { sanitized: val, foundTypes: [] };
}