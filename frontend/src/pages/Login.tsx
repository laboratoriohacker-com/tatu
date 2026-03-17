import { useState, type FormEvent } from "react";
import { TatuLogo } from "../components/TatuLogo";
import { GridPattern } from "../components/GridPattern";

interface LoginProps {
  onSendOtp: (email: string) => Promise<void>;
  onVerifyOtp: (code: string) => Promise<void>;
  otpSent: boolean;
  error: string | null;
}

export function Login({ onSendOtp, onVerifyOtp, otpSent, error }: LoginProps) {
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSendOtp = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    await onSendOtp(email);
    setLoading(false);
  };

  const handleVerify = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    await onVerifyOtp(code);
    setLoading(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-tatu-bg relative">
      <GridPattern />
      <div className="relative z-10 bg-tatu-surface border border-tatu-border rounded-lg p-8 w-80 flex flex-col items-center gap-6">
        <TatuLogo size={48} />
        <div className="text-center">
          <div className="text-xl font-bold tracking-widest text-tatu-text">TATU</div>
          <div className="text-[10px] text-tatu-text-dim tracking-widest uppercase mt-1">
            DevSecOps &amp; GRC - AI Assisted Platform
          </div>
        </div>

        {!otpSent ? (
          <form onSubmit={handleSendOtp} className="w-full flex flex-col gap-4">
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Email address"
              required
              className="w-full px-4 py-2.5 rounded-md bg-tatu-surface-alt border border-tatu-border text-tatu-text text-sm placeholder:text-tatu-text-dim focus:outline-none focus:border-tatu-accent"
            />
            {error && <div className="text-tatu-critical text-xs">{error}</div>}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-md bg-tatu-accent text-tatu-bg text-sm font-semibold hover:bg-tatu-accent-dim transition-colors disabled:opacity-50"
            >
              {loading ? "..." : "Send Code"}
            </button>
          </form>
        ) : (
          <form onSubmit={handleVerify} className="w-full flex flex-col gap-4">
            <p className="text-xs text-tatu-text-muted text-center">
              Enter the 6-digit code sent to your email
            </p>
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="000000"
              maxLength={6}
              required
              className="w-full px-4 py-2.5 rounded-md bg-tatu-surface-alt border border-tatu-border text-tatu-text text-sm text-center tracking-[0.5em] font-mono placeholder:text-tatu-text-dim focus:outline-none focus:border-tatu-accent"
            />
            {error && <div className="text-tatu-critical text-xs">{error}</div>}
            <button
              type="submit"
              disabled={loading || code.length !== 6}
              className="w-full py-2.5 rounded-md bg-tatu-accent text-tatu-bg text-sm font-semibold hover:bg-tatu-accent-dim transition-colors disabled:opacity-50"
            >
              {loading ? "..." : "Verify"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
