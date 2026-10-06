import React, { createContext, useContext, useEffect, useState } from 'react';
import { api } from '../api/client';
import type { Profile } from '../api/types';

interface AuthContextType {
  user: Profile | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (data: {
    full_name: string;
    username: string;
    email: string;
    birthday?: string | null;
    password: string;
    notice_version: string;
    notice_acknowledged: boolean;
  }) => Promise<void>;
  logout: () => Promise<void>;
  refreshProfile: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<Profile | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    checkSession();
  }, []);

  const checkSession = async () => {
    try {
      const session = await api.getSession();
      setUser(session.user);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (username: string, password: string) => {
    const session = await api.login({ username, password });
    setUser(session.user);
  };

  const register = async (data: {
    full_name: string;
    username: string;
    email: string;
    birthday?: string | null;
    password: string;
    notice_version: string;
    notice_acknowledged: boolean;
  }) => {
    const session = await api.register(data);
    setUser(session.user);
  };

  const logout = async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
    }
  };

  const refreshProfile = async () => {
    try {
      const { profile } = await api.getMe();
      setUser(profile);
    } catch {
      // Ignore
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshProfile }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

