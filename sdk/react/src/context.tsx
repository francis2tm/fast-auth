import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type PropsWithChildren
} from 'react';

import { client } from './generated/client.gen';
import {
  emailConfirmGet,
  emailConfirmSend,
  meGet,
  passwordForgot,
  passwordReset,
  signIn,
  signOut,
  signUp
} from './generated/sdk.gen';
import type {
  EmailConfirmResponse,
  EmailConfirmSendRequest,
  PasswordForgotRequest,
  PasswordResetRequest,
  SignInRequest,
  SignUpRequest,
  UserResponse
} from './generated/types.gen';

/**
 * Structured error raised by the SDK when the API returns a non-2xx response.
 */
export class FastAuthError extends Error {
  /**
   * HTTP status code returned by the API.
   */
  status: number;

  /**
   * Raw error payload returned by the generated client.
   */
  details: unknown;

  /**
   * Build a typed SDK error.
   */
  constructor(message: string, status: number, details: unknown) {
    super(message);
    this.name = 'FastAuthError';
    this.status = status;
    this.details = details;
  }
}

/**
 * Props used to initialize and control the auth provider.
 */
export type FastAuthProviderProps = PropsWithChildren<{
  /**
   * API base URL (e.g. http://localhost:30000).
   */
  baseUrl: string;
  /**
   * Fetch current user from `/auth/me` on mount.
   */
  autoLoadUser?: boolean;
  /**
   * Optional callback fired whenever user state changes.
   */
  onUserChange?: (user: UserResponse | null) => void;
}>;

/**
 * Public auth state and actions exposed through `useAuth()`.
 */
export type FastAuthContextValue = {
  /**
   * Current authenticated user. `null` means signed out.
   */
  user: UserResponse | null;
  /**
   * Loading indicator for auth bootstrap and in-flight actions.
   */
  loading: boolean;
  /**
   * Last action error message.
   */
  error: string | null;
  /**
   * Clear the in-memory error state.
   */
  errorClear: () => void;
  /**
   * Refresh current user from `/auth/me`.
   */
  userRefresh: () => Promise<UserResponse | null>;
  /**
   * Sign in and update user state.
   */
  signIn: (body: SignInRequest) => Promise<UserResponse>;
  /**
   * Sign up and update user state when cookies are issued.
   */
  signUp: (body: SignUpRequest) => Promise<UserResponse>;
  /**
   * Sign out and clear user state.
   */
  signOut: () => Promise<void>;
  /**
   * Send email confirmation message.
   */
  emailConfirmSend: (body: EmailConfirmSendRequest) => Promise<string>;
  /**
   * Confirm email using verification token.
   */
  emailConfirm: (token: string) => Promise<EmailConfirmResponse>;
  /**
   * Request password reset email.
   */
  passwordForgot: (body: PasswordForgotRequest) => Promise<string>;
  /**
   * Apply password reset token.
   */
  passwordReset: (body: PasswordResetRequest) => Promise<string>;
};

type ResultFields<T> = {
  data: T | undefined;
  error: unknown;
  response: Response;
};

const AUTH_ERROR_FALLBACK = 'Authentication request failed';

/**
 * Read best-effort message from generated error payloads.
 */
const errorMessageGet = (error: unknown): string => {
  if (typeof error === 'string' && error.length > 0) {
    return error;
  }

  if (error && typeof error === 'object' && 'error' in error) {
    const message = (error as { error?: unknown }).error;
    if (typeof message === 'string' && message.length > 0) {
      return message;
    }
  }

  return AUTH_ERROR_FALLBACK;
};

/**
 * Convert generated client result into data or throw a typed SDK error.
 */
const resultDataGet = <T,>(result: ResultFields<T>): T => {
  if (result.error || result.data === undefined) {
    throw new FastAuthError(
      errorMessageGet(result.error),
      result.response.status,
      result.error
    );
  }

  return result.data;
};

const FastAuthContext = createContext<FastAuthContextValue | undefined>(undefined);

/**
 * Context provider for fast-auth API state and actions.
 */
export const FastAuthProvider = ({
  baseUrl,
  autoLoadUser = true,
  onUserChange,
  children
}: FastAuthProviderProps) => {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(autoLoadUser);
  const [error, setError] = useState<string | null>(null);

  const userSet = useCallback(
    (nextUser: UserResponse | null) => {
      setUser(nextUser);
      onUserChange?.(nextUser);
    },
    [onUserChange]
  );

  useEffect(() => {
    client.setConfig({
      baseUrl,
      credentials: 'include'
    });
  }, [baseUrl]);

  const userRefresh = useCallback(async (): Promise<UserResponse | null> => {
    const result = (await meGet()) as ResultFields<UserResponse>;

    if (result.error || result.data === undefined) {
      if (result.response.status === 401) {
        userSet(null);
        setError(null);
        return null;
      }

      const message = errorMessageGet(result.error);
      setError(message);
      throw new FastAuthError(message, result.response.status, result.error);
    }

    userSet(result.data);
    setError(null);
    return result.data;
  }, [userSet]);

  useEffect(() => {
    if (!autoLoadUser) {
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);

    userRefresh()
      .catch(() => {
        if (!cancelled) {
          userSet(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [autoLoadUser, userRefresh, userSet]);

  const authSignIn = useCallback(async (body: SignInRequest): Promise<UserResponse> => {
    setLoading(true);
    try {
      const result = (await signIn({ body })) as ResultFields<{ user: UserResponse }>;
      const data = resultDataGet(result);
      userSet(data.user);
      setError(null);
      return data.user;
    } catch (errorValue) {
      const message = errorMessageGet(
        errorValue instanceof FastAuthError ? errorValue.details : errorValue
      );
      setError(message);
      throw errorValue;
    } finally {
      setLoading(false);
    }
  }, [userSet]);

  const authSignUp = useCallback(async (body: SignUpRequest): Promise<UserResponse> => {
    setLoading(true);
    try {
      const result = (await signUp({ body })) as ResultFields<{ user: UserResponse }>;
      const data = resultDataGet(result);
      userSet(data.user);
      setError(null);
      return data.user;
    } catch (errorValue) {
      const message = errorMessageGet(
        errorValue instanceof FastAuthError ? errorValue.details : errorValue
      );
      setError(message);
      throw errorValue;
    } finally {
      setLoading(false);
    }
  }, [userSet]);

  const authSignOut = useCallback(async (): Promise<void> => {
    setLoading(true);
    try {
      const result = (await signOut()) as ResultFields<unknown>;
      if (result.error && result.response.status !== 401) {
        throw new FastAuthError(
          errorMessageGet(result.error),
          result.response.status,
          result.error
        );
      }

      userSet(null);
      setError(null);
    } catch (errorValue) {
      const message = errorMessageGet(
        errorValue instanceof FastAuthError ? errorValue.details : errorValue
      );
      setError(message);
      throw errorValue;
    } finally {
      setLoading(false);
    }
  }, [userSet]);

  const authEmailConfirmSend = useCallback(
    async (body: EmailConfirmSendRequest): Promise<string> => {
      const result = (await emailConfirmSend({ body })) as ResultFields<{ message: string }>;
      const data = resultDataGet(result);
      setError(null);
      return data.message;
    },
    []
  );

  const authEmailConfirm = useCallback(async (token: string): Promise<EmailConfirmResponse> => {
    const result = (await emailConfirmGet({
      query: { token }
    })) as ResultFields<EmailConfirmResponse>;
    const data = resultDataGet(result);
    setError(null);
    return data;
  }, []);

  const authPasswordForgot = useCallback(
    async (body: PasswordForgotRequest): Promise<string> => {
      const result = (await passwordForgot({ body })) as ResultFields<{ message: string }>;
      const data = resultDataGet(result);
      setError(null);
      return data.message;
    },
    []
  );

  const authPasswordReset = useCallback(
    async (body: PasswordResetRequest): Promise<string> => {
      const result = (await passwordReset({ body })) as ResultFields<{ message: string }>;
      const data = resultDataGet(result);
      setError(null);
      return data.message;
    },
    []
  );

  const contextValue = useMemo<FastAuthContextValue>(
    () => ({
      user,
      loading,
      error,
      errorClear: () => setError(null),
      userRefresh,
      signIn: authSignIn,
      signUp: authSignUp,
      signOut: authSignOut,
      emailConfirmSend: authEmailConfirmSend,
      emailConfirm: authEmailConfirm,
      passwordForgot: authPasswordForgot,
      passwordReset: authPasswordReset
    }),
    [
      user,
      loading,
      error,
      userRefresh,
      authSignIn,
      authSignUp,
      authSignOut,
      authEmailConfirmSend,
      authEmailConfirm,
      authPasswordForgot,
      authPasswordReset
    ]
  );

  return (
    <FastAuthContext.Provider value={contextValue}>{children}</FastAuthContext.Provider>
  );
};

/**
 * Access fast-auth state and actions from React components.
 */
export const useAuth = (): FastAuthContextValue => {
  const context = useContext(FastAuthContext);
  if (!context) {
    throw new Error('useAuth must be used inside FastAuthProvider');
  }
  return context;
};
