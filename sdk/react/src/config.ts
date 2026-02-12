/**
 * Strict TOML shape expected by fast-auth runtime configuration.
 */
export type FastAuthTomlConfig = {
  frontend: FastAuthFrontendTomlConfig;
  jwt: FastAuthJwtTomlConfig;
  token: FastAuthTokenTomlConfig;
  password: FastAuthPasswordTomlConfig;
  cookie: FastAuthCookieTomlConfig;
  verification: FastAuthVerificationTomlConfig;
};

/**
 * Shared frontend settings used by auth links sent via email.
 */
export type FastAuthFrontendTomlConfig = {
  base_url: string;
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
 * Verification flow settings for email confirmation and password reset.
 */
export type FastAuthVerificationTomlConfig = {
  email_confirmation_require: boolean;
  email_token_expiry_secs: number;
  password_reset_token_expiry_secs: number;
};

type ConfigSectionValueMap = {
  frontend: FastAuthFrontendTomlConfig;
  jwt: FastAuthJwtTomlConfig;
  token: FastAuthTokenTomlConfig;
  password: FastAuthPasswordTomlConfig;
  cookie: FastAuthCookieTomlConfig;
  verification: FastAuthVerificationTomlConfig;
};

type ConfigSectionName = keyof ConfigSectionValueMap;
type PrimitiveKind = 'string' | 'boolean' | 'integer' | 'same_site';
type ConfigSectionSchema = {
  [S in ConfigSectionName]: {
    [K in keyof ConfigSectionValueMap[S]]: PrimitiveKind;
  };
};

const CONFIG_SECTION_SCHEMA: ConfigSectionSchema = {
  frontend: {
    base_url: 'string'
  },
  jwt: {
    issuer: 'string',
    audience: 'string'
  },
  token: {
    access_expiry_secs: 'integer',
    refresh_expiry_secs: 'integer'
  },
  password: {
    min_length: 'integer',
    max_length: 'integer',
    require_letter: 'boolean',
    require_number: 'boolean'
  },
  cookie: {
    access_token_name: 'string',
    refresh_token_name: 'string',
    domain: 'string',
    path: 'string',
    secure: 'boolean',
    same_site: 'same_site'
  },
  verification: {
    email_confirmation_require: 'boolean',
    email_token_expiry_secs: 'integer',
    password_reset_token_expiry_secs: 'integer'
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
    [S in ConfigSectionName]: Partial<ConfigSectionValueMap[S]>;
  } = {
    frontend: {},
    jwt: {},
    token: {},
    password: {},
    cookie: {},
    verification: {}
  };

  const declaredSections = new Set<string>();
  let currentSection: ConfigSectionName | null = null;

  const lines = tomlText.split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const rawLine = lineCommentStrip(lines[index] ?? '').trim();
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

    keyValueParse(rawLine, lineNumber, currentSection, values);
  }

  const config: FastAuthTomlConfig = {
    frontend: sectionCompleteGet('frontend', values),
    jwt: sectionCompleteGet('jwt', values),
    token: sectionCompleteGet('token', values),
    password: sectionCompleteGet('password', values),
    cookie: sectionCompleteGet('cookie', values),
    verification: sectionCompleteGet('verification', values)
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

  const table = value as Record<string, unknown>;
  const exactKeys = [
    'frontend',
    'jwt',
    'token',
    'password',
    'cookie',
    'verification'
  ];
  objectUnknownKeyReject(table, exactKeys, 'config');

  const config: FastAuthTomlConfig = {
    frontend: recordTypedGet(table.frontend, 'frontend') as FastAuthFrontendTomlConfig,
    jwt: recordTypedGet(table.jwt, 'jwt') as FastAuthJwtTomlConfig,
    token: recordTypedGet(table.token, 'token') as FastAuthTokenTomlConfig,
    password: recordTypedGet(table.password, 'password') as FastAuthPasswordTomlConfig,
    cookie: recordTypedGet(table.cookie, 'cookie') as FastAuthCookieTomlConfig,
    verification: recordTypedGet(
      table.verification,
      'verification'
    ) as FastAuthVerificationTomlConfig
  };

  configSectionValidate('frontend', config.frontend as Record<string, unknown>);
  configSectionValidate('jwt', config.jwt as Record<string, unknown>);
  configSectionValidate('token', config.token as Record<string, unknown>);
  configSectionValidate('password', config.password as Record<string, unknown>);
  configSectionValidate('cookie', config.cookie as Record<string, unknown>);
  configSectionValidate('verification', config.verification as Record<string, unknown>);

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
): ConfigSectionName => {
  if (!rawLine.endsWith(']')) {
    throw new FastAuthConfigParseError('invalid section header', lineNumber);
  }

  const sectionName = rawLine.slice(1, -1).trim();
  const knownSections = new Set<ConfigSectionName>([
    'frontend',
    'jwt',
    'token',
    'password',
    'cookie',
    'verification'
  ]);

  if (!knownSections.has(sectionName as ConfigSectionName)) {
    throw new FastAuthConfigParseError(`unknown section: [${sectionName}]`, lineNumber);
  }

  if (declaredSections.has(sectionName)) {
    throw new FastAuthConfigParseError(
      `duplicate section declaration: [${sectionName}]`,
      lineNumber
    );
  }

  declaredSections.add(sectionName);
  return sectionName as ConfigSectionName;
};

/**
 * Parse and assign a key/value line for the active section.
 */
const keyValueParse = (
  rawLine: string,
  lineNumber: number,
  section: ConfigSectionName,
  values: { [S in ConfigSectionName]: Partial<ConfigSectionValueMap[S]> }
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

  const schema = CONFIG_SECTION_SCHEMA[section] as Record<string, PrimitiveKind>;
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
  section: ConfigSectionName,
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
const sectionCompleteGet = <S extends ConfigSectionName>(
  section: S,
  values: { [K in ConfigSectionName]: Partial<ConfigSectionValueMap[K]> }
): ConfigSectionValueMap[S] => {
  const schema = CONFIG_SECTION_SCHEMA[section] as Record<string, PrimitiveKind>;
  const sectionValues = values[section] as Record<string, unknown>;

  for (const key of Object.keys(schema)) {
    if (!Object.prototype.hasOwnProperty.call(sectionValues, key)) {
      throw new FastAuthConfigParseError(`missing required key '${key}' in [${section}]`);
    }
  }

  return sectionValues as ConfigSectionValueMap[S];
};

/**
 * Validate high-level semantic constraints shared with server config checks.
 */
const semanticsValidate = (config: FastAuthTomlConfig): void => {
  const { token, password, verification, frontend } = config;

  if (token.access_expiry_secs <= 0) {
    throw new FastAuthConfigParseError('token.access_expiry_secs must be greater than 0');
  }

  if (token.refresh_expiry_secs <= 0) {
    throw new FastAuthConfigParseError('token.refresh_expiry_secs must be greater than 0');
  }

  if (password.min_length <= 0) {
    throw new FastAuthConfigParseError('password.min_length must be greater than 0');
  }

  if (password.max_length < password.min_length) {
    throw new FastAuthConfigParseError(
      'password.max_length must be greater than or equal to password.min_length'
    );
  }

  if (verification.email_token_expiry_secs <= 0) {
    throw new FastAuthConfigParseError(
      'verification.email_token_expiry_secs must be greater than 0'
    );
  }

  if (verification.password_reset_token_expiry_secs <= 0) {
    throw new FastAuthConfigParseError(
      'verification.password_reset_token_expiry_secs must be greater than 0'
    );
  }

  if (verification.email_confirmation_require && frontend.base_url.trim().length === 0) {
    throw new FastAuthConfigParseError(
      'frontend.base_url must be set when verification.email_confirmation_require=true'
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
const configSectionValidate = (
  section: ConfigSectionName,
  value: Record<string, unknown>
): void => {
  const schema = CONFIG_SECTION_SCHEMA[section] as Record<string, PrimitiveKind>;
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
  section: ConfigSectionName,
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
