import { MantineProvider } from '@mantine/core'
import { Notifications } from '@mantine/notifications'
import '@mantine/core/styles.css'
import '@mantine/notifications/styles.css'
import './mantine.css'
import { useTheme } from './ThemeProvider.jsx'

/**
 * Connects our dark / light switch to the Mantine UI library.
 * Mantine draws the buttons, loaders, pop-ups, badges, tags and inputs.
 * The colours still come from theme.css (see mantine.css).
 */
export default function MantineBridge({ children }) {
  const { theme } = useTheme()
  return (
    <MantineProvider forceColorScheme={theme} defaultColorScheme="dark">
      <Notifications position="bottom-right" />
      {children}
    </MantineProvider>
  )
}
