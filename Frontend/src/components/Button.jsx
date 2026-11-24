import { Button as MantineButton } from '@mantine/core'
import Icon from './Icon.jsx'

/**
 * Our button. It is the Mantine button (an npm package) with the same props the app already uses:
 *   variant: 'primary' (filled) or 'outline'
 *   tone:    'default' or 'danger'
 *   size:    'sm' for a small one
 *   icon:    name of an animated icon
 *   busy:    shows a spinner and disables the button
 */
export default function Button({ variant = 'outline', tone = 'default', size, icon, busy, children, ...rest }) {
  const mantineVariant = variant === 'primary' ? 'filled' : 'outline'
  const mantineSize = size === 'sm' ? 'compact-sm' : 'sm'

  let leftIcon = null
  if (icon) {
    leftIcon = <Icon name={icon} size={18} />
  }

  return (
    <MantineButton
      variant={mantineVariant}
      size={mantineSize}
      data-tone={tone}
      loading={busy}
      leftSection={leftIcon}
      disabled={rest.disabled}
      {...rest}
    >
      {children}
    </MantineButton>
  )
}
