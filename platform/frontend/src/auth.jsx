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
      .then((u) => u && u.role && setUser(u))
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
  const logout = () => {
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
