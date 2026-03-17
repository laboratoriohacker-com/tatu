import { useState, useCallback } from "react";
import { api } from "../lib/api";
import type { AuthUser } from "../lib/types";

export function useAuth() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [otpSent, setOtpSent] = useState(false);
  const [loginEmail, setLoginEmail] = useState("");

  const sendOtp = useCallback(async (email: string) => {
    try {
      setError(null);
      await api.login(email);
      setLoginEmail(email);
      setOtpSent(true);
    } catch {
      setError("Invalid email or account inactive");
    }
  }, []);

  const verifyOtp = useCallback(async (code: string) => {
    try {
      setError(null);
      await api.verifyOtp(loginEmail, code);
      const me = (await api.getMe()) as AuthUser;
      setUser(me);
      setIsAuthenticated(true);
    } catch {
      setError("Invalid or expired code");
    }
  }, [loginEmail]);

  const checkAuth = useCallback(async () => {
    try {
      const me = (await api.getMe()) as AuthUser;
      setUser(me);
      setIsAuthenticated(true);
    } catch {
      setIsAuthenticated(false);
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // ignore
    }
    setUser(null);
    setIsAuthenticated(false);
    setOtpSent(false);
    setLoginEmail("");
    setError(null);
  }, []);

  return { user, isAuthenticated, error, otpSent, sendOtp, verifyOtp, checkAuth, logout };
}
