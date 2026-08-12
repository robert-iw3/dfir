import { createContext, useContext, useEffect, useState } from "react";
import { api, clearToken, getToken, setToken } from "./api.js";

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);
  // The platform is unreachable or erroring, as opposed to the analyst not being signed in.
  const [down, setDown] = useState(false);

  useEffect(() => {
    // Always try /api/me first: under SSO the request is already authenticated by the
    // oauth2-proxy session (no token needed). If it fails, fall back to token login.
    let cancelled = false;
    let timer = null;

    // "Not signed in" and "the platform is not answering" are different facts, and only the
    // first has anything to do with the analyst. Treating them alike put a local password
    // form in front of a kiosk whose users authenticate through Keycloak and have no local
    // password — a dead end dressed as a login.
    const bootstrap = () => {
      api.me()
        .then((u) => {
          if (cancelled) return;
          if (u && u.role) setUser(u);
          setDown(false);
          // The gate's error page sets this to bound its automatic retry to one attempt.
          // Reaching an authenticated app means the retry is spent, so a later failed login
          // in this tab gets its own attempt instead of going straight to the dead end.
          try { sessionStorage.removeItem("oauth2-retry"); } catch { /* not available */ }
        })
        .catch((err) => {
          if (cancelled) return;
          // 5xx or no response at all: the platform is down or restarting. Say so and keep
          // trying, rather than asking for credentials that would not help.
          if (!err?.status || err.status >= 500) {
            setDown(true);
            timer = setTimeout(bootstrap, 5000);
            return;
          }
          setDown(false);
          if (getToken()) clearToken();
        })
        .finally(() => { if (!cancelled) setReady(true); });
    };
    bootstrap();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, []);

  const login = async (username, password) => {
    const { token } = await api.login(username, password);
    setToken(token);
    setUser(await api.me());
  };
  // Sign-out must end all three sessions: the local token, the oauth2-proxy cookie, and the
  // Keycloak session. Leaving the IdP session alive would re-authenticate the next request
  // silently, so the user never appears logged out.
  const logout = async () => {
    try {
      await api.logout();
    } catch {
      /* recorded or not, the session still has to end */
    }
    clearToken();
    setUser(null);
    window.location.href = "/oauth2/sign_out?rd=" + encodeURIComponent("/");
  };

  return (
    <AuthCtx.Provider value={{ user, ready, login, logout, down }}>
      {children}
    </AuthCtx.Provider>
  );
}

export const useAuth = () => useContext(AuthCtx);
export const can = (user, ...roles) => user && roles.includes(user.role);
