import Icon from '../components/Icon.jsx'
import { useTheme } from './ThemeProvider.jsx'

/** Light / dark switch button (used in the sidebar footer). */
export default function ThemeToggle() {
  const { theme, toggle } = useTheme()
  const next = theme === 'dark' ? 'light' : 'dark'
  return (
    <button className="theme-toggle" onClick={toggle} aria-label={`Switch to ${next} mode`}>
      <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={22} />
      {theme === 'dark' ? 'Light mode' : 'Dark mode'}
    </button>
  )
}
