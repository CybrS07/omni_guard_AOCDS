import { createContext, useContext, useState } from 'react'

const AuthContext = createContext(null)

// Holds the token the agent gives after face verify.
// For now login() can be called with any token so you can build the UI before the backend exists.
export function AuthProvider({ children }) {
  const [token, setToken] = useState(null)
  const login = (t = 'dev-token') => setToken(t)
  const logout = () => setToken(null)
  return (
    <AuthContext.Provider value={{ token, isAuthed: !!token, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
