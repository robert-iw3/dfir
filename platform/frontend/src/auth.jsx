import { createContext, useContext, useEffect, useState } from "react";
import { api, clearToken, getToken, setToken } from "./api.js";

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    // Always try /api/me first: under SSO the request is already authenticated by the
    // oauth2-proxy session (no token needed). If it fails, fall back to token login.
    api.me()
      .then((u) => {
        if (u && u.role) setUser(u);
        // The gate's error page sets this to bound its automatic retry to one attempt.
        // Reaching an authenticated app means the retry is spent, so a later failed login
        // in this tab gets its own attempt instead of going straight to the dead end.
        try { sessionStorage.removeItem("oauth2-retry"); } catch { /* not available */ }
      })
      .catch(() => { if (getToken()) clearToken(); })
      .finally(() => setReady(true));
  }, []);

  const login = async (username, password) => {
    const { token } = await api.login(username, password);
    setToken(token);
    setUser(await api.me());
  };
  // Sign-out must end all three sessions: the local token, the oauth2-proxy cookie, and
  // the Keycloak session. Leaving the IdP session alive would re-authenticate the next
  // request silently, so the user never appears logged out.
  //
  // Hitting the gate's sign-out covers all three: it clears its own cookie and ends the
  // Keycloak session over the back channel (`--backend-logout-url`). Returning to `/`
  // then has no session anywhere and lands on the Keycloak login page.
  //
  // The platform is told first, while the session still authenticates: once the gate has
  // cleared the cookie there is no identity left to attribute the sign-out to, and the audit
  // trail would show sign-ons that never end. A failure to record it does not block the
  // sign-out — leaving someone signed in because the trail is unavailable is the worse of
  // the two outcomes.
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
    <AuthCtx.Provider value={{ user, ready, login, logout }}>
      {children}
    </AuthCtx.Provider>
  );
}

export const useAuth = () => useContext(AuthCtx);
export const can = (user, ...roles) => user && roles.includes(user.role);
