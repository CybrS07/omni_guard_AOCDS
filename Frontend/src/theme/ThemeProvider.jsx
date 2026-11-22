import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import './theme.css'

/**
 * Theme component. Colours live in ./theme.css; this file only decides WHICH set is active
 * ("dark" | "light"), remembers it, and exposes it with useTheme().
 * index.html sets the same attribute before first paint so there is no flash.
 */
const KEY = 'soc-theme'
const ThemeCtx = createContext({ theme: 'dark', toggle: () => {}, setTheme: () => {} })

function initial() {
  try {
    const saved = localStorage.getItem(KEY)
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    /* storage can be blocked */
  }
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(initial)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem(KEY, theme)
    } catch {
      /* ignore */
    }
  }, [theme])

  const toggle = useCallback(() => setTheme((t) => (t === 'dark' ? 'light' : 'dark')), [])
  const value = useMemo(() => ({ theme, toggle, setTheme }), [theme, toggle])
  return <ThemeCtx.Provider value={value}>{children}</ThemeCtx.Provider>
}

export const useTheme = () => useContext(ThemeCtx)
