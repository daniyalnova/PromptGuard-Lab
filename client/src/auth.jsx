import { createContext, useContext, useEffect, useState, useCallback } from 'react'; import { get, post } from './api.js';
const Ctx = createContext(null); export const useAuth = () => useContext(Ctx);
export function AuthProvider({ children }) {
  const [user, setUser] = useState(undefined);            // undefined = loading, null = signed out
  const refresh = useCallback(() => get('/auth/me', { noRefresh: false }).then(setUser).catch(() => setUser(null)), []);
  useEffect(() => { refresh(); }, [refresh]);
  const logout = async () => { try { await post('/auth/logout'); } catch {} setUser(null); };
  return <Ctx.Provider value={{ user, setUser, refresh, logout }}>{children}</Ctx.Provider>;
}
