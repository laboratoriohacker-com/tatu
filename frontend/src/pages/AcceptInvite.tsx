import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { TatuLogo } from "../components/TatuLogo";
import { GridPattern } from "../components/GridPattern";

export function AcceptInvite() {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    const token = searchParams.get("token");

    const run = async () => {
      if (!token) {
        setErrorMsg("Missing invite token.");
        setStatus("error");
        return;
      }
      try {
        await api.acceptInvite(token);
        setStatus("success");
      } catch (err: unknown) {
        setErrorMsg(err instanceof Error ? err.message : "Invalid or expired invite token.");
        setStatus("error");
      }
    };

    run();
  }, [searchParams]);

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

        {status === "loading" && (
          <p className="text-sm text-tatu-text-muted">Activating your account...</p>
        )}

        {status === "success" && (
          <div className="w-full flex flex-col items-center gap-4">
            <p className="text-sm text-tatu-accent text-center font-semibold">
              Account activated! You can now log in.
            </p>
            <a
              href="/"
              className="w-full py-2.5 rounded-md bg-tatu-accent text-tatu-bg text-sm font-semibold hover:bg-tatu-accent-dim transition-colors text-center"
            >
              Go to Login
            </a>
          </div>
        )}

        {status === "error" && (
          <div className="w-full flex flex-col items-center gap-4">
            <p className="text-sm text-tatu-critical text-center">
              {errorMsg ?? "Something went wrong."}
            </p>
            <a
              href="/"
              className="text-xs text-tatu-text-muted hover:text-tatu-accent transition-colors"
            >
              Back to login
            </a>
          </div>
        )}
      </div>
    </div>
  );
}
