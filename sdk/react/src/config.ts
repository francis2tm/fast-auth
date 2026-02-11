/**
 * Strict TOML shape expected by fast-auth runtime configuration.
 */
export type FastAuthTomlConfig = {
  auth: {
    jwt: FastAuthJwtTomlConfig;
    token: FastAuthTokenTomlConfig;
    password: FastAuthPasswordTomlConfig;
    cookie: FastAuthCookieTomlConfig;
    email: FastAuthEmailTomlConfig;
  };
};

/**
 * JWT claims configuration.
 */
export type FastAuthJwtTomlConfig = {
  issuer: string;
  audience: string;
};

/**
 * Token expiry configuration (seconds).
 */
export type FastAuthTokenTomlConfig = {
  access_expiry_secs: number;
  refresh_expiry_secs: number;
};

/**
 * Password policy configuration.
 */
export type FastAuthPasswordTomlConfig = {
  min_length: number;
  max_length: number;
  require_letter: boolean;
  require_number: boolean;
};

/**
 * Cookie policy configuration.
 */
export type FastAuthCookieTomlConfig = {
  access_token_name: string;
  refresh_token_name: string;
  domain: string;
  path: string;
  secure: boolean;
  same_site: FastAuthCookieSameSite;
};

/**
 * Cookie SameSite strategy.
 */
export type FastAuthCookieSameSite = 'none' | 'lax' | 'strict';

/**
 * Email and verification configuration.
 */
export type FastAuthEmailTomlConfig = {
  verification_token_expiry_secs: number;
  password_reset_token_expiry_secs: number;
  link_base_url: string;
  confirmation_require: boolean;
};

type AuthSectionValueMap = {
  'auth.jwt': FastAuthJwtTomlConfig;
  'auth.token': FastAuthTokenTomlConfig;
  'auth.password': FastAuthPasswordTomlConfig;
  'auth.cookie': FastAuthCookieTomlConfig;
  'auth.email': FastAuthEmailTomlConfig;
};

type AuthSectionName = keyof AuthSectionValueMap;
type PrimitiveKind = 'string' | 'boolean' | 'integer' | 'same_site';
type AuthSectionSchema = {
  [S in AuthSectionName]: {
    [K in keyof AuthSectionValueMap[S]]: PrimitiveKind;
  };
};

const AUTH_SECTION_SCHEMA: AuthSectionSchema = {
  'auth.jwt': {
    issuer: 'string',
    audience: 'string'
  },
  'auth.token': {
    access_expiry_secs: 'integer',
    refresh_expiry_secs: 'integer'
  },
  'auth.password': {
    min_length: 'integer',
    max_length: 'integer',
    require_letter: 'boolean',
    require_number: 'boolean'
  },
  'auth.cookie': {
    access_token_name: 'string',
    refresh_token_name: 'string',
    domain: 'string',
    path: 'string',
    secure: 'boolean',
    same_site: 'same_site'
  },
  'auth.email': {
    verification_token_expiry_secs: 'integer',
    password_reset_token_expiry_secs: 'integer',
    link_base_url: 'string',
    confirmation_require: 'boolean'
  }
};

/**
 * Error raised when SDK TOML parsing or strict validation fails.
 */
export class FastAuthConfigParseError extends Error {
  /**
   * 1-based line number associated with the failure when available.
   */
  line: number | null;

  /**
   * Build a typed parser error with optional line context.
   */
  constructor(message: string, line: number | null = null) {
    super(message);
    this.name = 'FastAuthConfigParseError';
    this.line = line;
  }
}

/**
 * Parse fast-auth TOML text into a strict typed configuration.
 *
 * This parser is intentionally strict:
 * - unknown sections/keys are rejected
 * - duplicate sections/keys are rejected
 * - only scalar values required by fast-auth are accepted
 */
export const authConfigParseToml = (tomlText: string): FastAuthTomlConfig => {
  const values: {
    [S in AuthSectionName]: Partial<AuthSectionValueMap[S]>;
  } = {
    'auth.jwt': {},
    'auth.token': {},
    'auth.password': {},
    'auth.cookie': {},
    'auth.email': {}
  };

  const declaredSections = new Set<string>();
  let currentSection: AuthSectionName | 'auth' | null = null;

  const lines = tomlText.split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const rawLine = lineCommentStrip(lines[index]).trim();
    if (rawLine.length === 0) {
      continue;
    }

    if (rawLine.startsWith('[')) {
      currentSection = sectionParse(rawLine, lineNumber, declaredSections);
      continue;
    }

    if (currentSection === null) {
      throw new FastAuthConfigParseError(
        'key/value must be inside a section header',
        lineNumber
      );
    }

    if (currentSection === 'auth') {
      throw new FastAuthConfigParseError(
        'root [auth] section cannot contain direct keys; use [auth.<domain>]',
        lineNumber
      );
    }

    keyValueParse(rawLine, lineNumber, currentSection, values);
  }

  const jwt = sectionCompleteGet('auth.jwt', values);
  const token = sectionCompleteGet('auth.token', values);
  const password = sectionCompleteGet('auth.password', values);
  const cookie = sectionCompleteGet('auth.cookie', values);
  const email = sectionCompleteGet('auth.email', values);

  const config: FastAuthTomlConfig = {
    auth: {
      jwt,
      token,
      password,
      cookie,
      email
    }
  };

  semanticsValidate(config);
  return config;
};

/**
 * Validate already parsed config-like data against the strict schema.
 */
export const authConfigValidate = (value: unknown): FastAuthTomlConfig => {
  if (typeof value !== 'object' || value === null) {
    throw new FastAuthConfigParseError('config must be an object');
  }

  if (!('auth' in value)) {
    throw new FastAuthConfigParseError('missing required root key: auth');
  }

  const authRecord = (value as { auth: unknown }).auth;
  if (typeof authRecord !== 'object' || authRecord === null) {
    throw new FastAuthConfigParseError('auth must be an object');
  }

  const table = authRecord as Record<string, unknown>;
  const exactKeys = ['jwt', 'token', 'password', 'cookie', 'email'];
  objectUnknownKeyReject(table, exactKeys, 'auth');

  const config = {
    auth: {
      jwt: recordTypedGet(table.jwt, 'auth.jwt'),
      token: recordTypedGet(table.token, 'auth.token'),
      password: recordTypedGet(table.password, 'auth.password'),
      cookie: recordTypedGet(table.cookie, 'auth.cookie'),
      email: recordTypedGet(table.email, 'auth.email')
    }
  } as FastAuthTomlConfig;

  authSectionValidate('auth.jwt', config.auth.jwt);
  authSectionValidate('auth.token', config.auth.token);
  authSectionValidate('auth.password', config.auth.password);
  authSectionValidate('auth.cookie', config.auth.cookie);
  authSectionValidate('auth.email', config.auth.email);

  semanticsValidate(config);
  return config;
};

/**
 * Parse and validate strict config from TOML text.
 */
export const authConfigParseAndValidateToml = (
  tomlText: string
): FastAuthTomlConfig => authConfigValidate(authConfigParseToml(tomlText));

/**
 * Strip comments while preserving hash symbols inside quoted strings.
 */
const lineCommentStrip = (line: string): string => {
  let inString = false;
  let escaped = false;
  let output = '';

  for (const char of line) {
    if (char === '"' && !escaped) {
      inString = !inString;
      output += char;
      continue;
    }

    if (char === '#' && !inString) {
      break;
    }

    output += char;
    escaped = char === '\\' && !escaped;
    if (char !== '\\') {
      escaped = false;
    }
  }

  return output;
};

/**
 * Parse and validate a TOML section header.
 */
const sectionParse = (
  rawLine: string,
  lineNumber: number,
  declaredSections: Set<string>
): AuthSectionName | 'auth' => {
  if (!rawLine.endsWith(']')) {
    throw new FastAuthConfigParseError('invalid section header', lineNumber);
  }

  const sectionName = rawLine.slice(1, -1).trim();
  const knownSections = new Set<AuthSectionName>([
    'auth.jwt',
    'auth.token',
    'auth.password',
    'auth.cookie',
    'auth.email'
  ]);

  if (sectionName !== 'auth' && !knownSections.has(sectionName as AuthSectionName)) {
    throw new FastAuthConfigParseError(`unknown section: [${sectionName}]`, lineNumber);
  }

  if (declaredSections.has(sectionName)) {
    throw new FastAuthConfigParseError(
      `duplicate section declaration: [${sectionName}]`,
      lineNumber
    );
  }

  declaredSections.add(sectionName);
  return sectionName as AuthSectionName | 'auth';
};

/**
 * Parse and assign a key/value line for the active section.
 */
const keyValueParse = (
  rawLine: string,
  lineNumber: number,
  section: AuthSectionName,
  values: { [S in AuthSectionName]: Partial<AuthSectionValueMap[S]> }
): void => {
  const separator = rawLine.indexOf('=');
  if (separator <= 0) {
    throw new FastAuthConfigParseError('invalid key/value expression', lineNumber);
  }

  const key = rawLine.slice(0, separator).trim();
  const valueText = rawLine.slice(separator + 1).trim();
  if (key.length === 0 || valueText.length === 0) {
    throw new FastAuthConfigParseError('invalid key/value expression', lineNumber);
  }

  const schema = AUTH_SECTION_SCHEMA[section] as Record<string, PrimitiveKind>;
  const expectedKind = schema[key];
  if (!expectedKind) {
    throw new FastAuthConfigParseError(`unknown key '${key}' in [${section}]`, lineNumber);
  }

  const sectionValues = values[section] as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(sectionValues, key)) {
    throw new FastAuthConfigParseError(
      `duplicate key '${key}' in [${section}]`,
      lineNumber
    );
  }

  sectionValues[key] = primitiveParse(valueText, expectedKind, section, key, lineNumber);
};

/**
 * Parse primitive value according to strict expected kind.
 */
const primitiveParse = (
  valueText: string,
  kind: PrimitiveKind,
  section: AuthSectionName,
  key: string,
  lineNumber: number
): string | boolean | number => {
  if (kind === 'boolean') {
    if (valueText === 'true') {
      return true;
    }
    if (valueText === 'false') {
      return false;
    }
    throw new FastAuthConfigParseError(
      `expected boolean for [${section}].${key}`,
      lineNumber
    );
  }

  if (kind === 'integer') {
    if (!/^\d+$/u.test(valueText)) {
      throw new FastAuthConfigParseError(
        `expected non-negative integer for [${section}].${key}`,
        lineNumber
      );
    }

    const parsed = Number.parseInt(valueText, 10);
    if (!Number.isSafeInteger(parsed)) {
      throw new FastAuthConfigParseError(
        `integer out of range for [${section}].${key}`,
        lineNumber
      );
    }

    return parsed;
  }

  if (!(valueText.startsWith('"') && valueText.endsWith('"'))) {
    throw new FastAuthConfigParseError(
      `expected quoted string for [${section}].${key}`,
      lineNumber
    );
  }

  let parsedString: string;
  try {
    parsedString = JSON.parse(valueText) as string;
  } catch {
    throw new FastAuthConfigParseError(
      `invalid string literal for [${section}].${key}`,
      lineNumber
    );
  }

  if (kind === 'same_site') {
    if (parsedString === 'none' || parsedString === 'lax' || parsedString === 'strict') {
      return parsedString;
    }
    throw new FastAuthConfigParseError(
      `expected one of "none" | "lax" | "strict" for [${section}].${key}`,
      lineNumber
    );
  }

  return parsedString;
};

/**
 * Ensure a parsed section has all required keys and return a typed value.
 */
const sectionCompleteGet = <S extends AuthSectionName>(
  section: S,
  values: { [K in AuthSectionName]: Partial<AuthSectionValueMap[K]> }
): AuthSectionValueMap[S] => {
  const schema = AUTH_SECTION_SCHEMA[section] as Record<string, PrimitiveKind>;
  const sectionValues = values[section] as Record<string, unknown>;

  for (const key of Object.keys(schema)) {
    if (!Object.prototype.hasOwnProperty.call(sectionValues, key)) {
      throw new FastAuthConfigParseError(`missing required key '${key}' in [${section}]`);
    }
  }

  return sectionValues as AuthSectionValueMap[S];
};

/**
 * Validate high-level semantic constraints shared with server config checks.
 */
const semanticsValidate = (config: FastAuthTomlConfig): void => {
  const { token, password, email } = config.auth;

  if (token.access_expiry_secs <= 0) {
    throw new FastAuthConfigParseError(
      'auth.token.access_expiry_secs must be greater than 0'
    );
  }

  if (token.refresh_expiry_secs <= 0) {
    throw new FastAuthConfigParseError(
      'auth.token.refresh_expiry_secs must be greater than 0'
    );
  }

  if (password.min_length <= 0) {
    throw new FastAuthConfigParseError(
      'auth.password.min_length must be greater than 0'
    );
  }

  if (password.max_length < password.min_length) {
    throw new FastAuthConfigParseError(
      'auth.password.max_length must be greater than or equal to auth.password.min_length'
    );
  }

  if (email.verification_token_expiry_secs <= 0) {
    throw new FastAuthConfigParseError(
      'auth.email.verification_token_expiry_secs must be greater than 0'
    );
  }

  if (email.password_reset_token_expiry_secs <= 0) {
    throw new FastAuthConfigParseError(
      'auth.email.password_reset_token_expiry_secs must be greater than 0'
    );
  }

  if (email.confirmation_require && email.link_base_url.trim().length === 0) {
    throw new FastAuthConfigParseError(
      'auth.email.link_base_url must be set when auth.email.confirmation_require=true'
    );
  }
};

/**
 * Reject unknown keys for an object record.
 */
const objectUnknownKeyReject = (
  record: Record<string, unknown>,
  allowedKeys: string[],
  parentPath: string
): void => {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new FastAuthConfigParseError(`unknown key '${parentPath}.${key}'`);
    }
  }
};

/**
 * Convert unknown value to object record or throw.
 */
const recordTypedGet = (
  value: unknown,
  path: string
): Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) {
    throw new FastAuthConfigParseError(`${path} must be an object`);
  }

  return value as Record<string, unknown>;
};

/**
 * Validate a section object against strict field schema and value types.
 */
const authSectionValidate = (
  section: AuthSectionName,
  value: Record<string, unknown>
): void => {
  const schema = AUTH_SECTION_SCHEMA[section] as Record<string, PrimitiveKind>;
  objectUnknownKeyReject(value, Object.keys(schema), section);

  for (const [key, kind] of Object.entries(schema)) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      throw new FastAuthConfigParseError(`missing required key '${section}.${key}'`);
    }

    primitiveValidate(value[key], kind, section, key);
  }
};

/**
 * Validate primitive field value against schema kind.
 */
const primitiveValidate = (
  value: unknown,
  kind: PrimitiveKind,
  section: AuthSectionName,
  key: string
): void => {
  if (kind === 'string') {
    if (typeof value !== 'string') {
      throw new FastAuthConfigParseError(`expected string for ${section}.${key}`);
    }
    return;
  }

  if (kind === 'boolean') {
    if (typeof value !== 'boolean') {
      throw new FastAuthConfigParseError(`expected boolean for ${section}.${key}`);
    }
    return;
  }

  if (kind === 'integer') {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw new FastAuthConfigParseError(
        `expected non-negative integer for ${section}.${key}`
      );
    }
    return;
  }

  if (value !== 'none' && value !== 'lax' && value !== 'strict') {
    throw new FastAuthConfigParseError(
      `expected one of "none" | "lax" | "strict" for ${section}.${key}`
    );
  }
};
