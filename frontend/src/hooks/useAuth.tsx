import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { User } from '@/types';
import { authApi } from '@/lib/api';

export interface ExtendedUser extends User {
  email?: string;
  email_verified?: boolean;
  mfa_enabled?: boolean;
  notifications?: Array<{
    id: string;
    title: string;
    description: string;
    time: string;
    unread?: boolean;
  }>;
}

interface AuthContextType {
  user: ExtendedUser | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  updateUser: (updates: Partial<ExtendedUser>) => void;
  markNotificationsRead: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function buildDefaultUser(rawUser: any): ExtendedUser {
  return {
    ...rawUser,
    email:
      rawUser?.email ||
      `${rawUser?.username || 'analyst'}@phishguard.local`,
    email_verified: rawUser?.email_verified ?? false,
    mfa_enabled: rawUser?.mfa_enabled ?? false,
    notifications:
      rawUser?.notifications ?? [
        {
          id: '1',
          title: 'Welcome to PhishGuard SOC',
          description: 'Your analyst workspace is ready.',
          time: 'Just now',
          unread: true,
        },
        {
          id: '2',
          title: 'Security recommendation',
          description: 'Enable MFA to secure your account.',
          time: 'Today',
          unread: true,
        },
      ],
  };
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<ExtendedUser | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const storedToken = localStorage.getItem('pg_token');
    const storedUser = localStorage.getItem('pg_user');

    if (storedToken && storedUser) {
      try {
        const parsed = JSON.parse(storedUser);
        const hydrated = buildDefaultUser(parsed);
        setToken(storedToken);
        setUser(hydrated);
        localStorage.setItem('pg_user', JSON.stringify(hydrated));
      } catch {
        localStorage.removeItem('pg_token');
        localStorage.removeItem('pg_user');
      }
    }

    setIsLoading(false);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const data = await authApi.login(username, password);
    const normalizedUser = buildDefaultUser(data.user);

    localStorage.setItem('pg_token', data.access_token);
    localStorage.setItem('pg_user', JSON.stringify(normalizedUser));

    setToken(data.access_token);
    setUser(normalizedUser);
  }, []);

  const logout = useCallback(() => {
    authApi.logout().catch(() => { });
    localStorage.removeItem('pg_token');
    localStorage.removeItem('pg_user');
    setToken(null);
    setUser(null);
  }, []);

  const updateUser = useCallback((updates: Partial<ExtendedUser>) => {
    setUser((prev) => {
      if (!prev) return prev;
      const next = { ...prev, ...updates };
      localStorage.setItem('pg_user', JSON.stringify(next));
      return next;
    });
  }, []);

  const markNotificationsRead = useCallback(() => {
    setUser((prev) => {
      if (!prev) return prev;
      const next = {
        ...prev,
        notifications: (prev.notifications || []).map((item) => ({
          ...item,
          unread: false,
        })),
      };
      localStorage.setItem('pg_user', JSON.stringify(next));
      return next;
    });
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token && !!user,
        isLoading,
        login,
        logout,
        updateUser,
        markNotificationsRead,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}