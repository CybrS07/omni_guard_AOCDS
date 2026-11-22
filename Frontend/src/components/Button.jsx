import Icon from './Icon.jsx'

/**
 * variant: 'primary' | 'outline' | 'uiverse-a' | 'uiverse-b'
 * tone:    'default' | 'danger'
 * See ui.css for how to drop in the original Uiverse CSS.
 */
export default function Button({ variant = 'outline', tone = 'default', size, icon, busy, children, className = '', ...rest }) {
  const cls = [
    'btn',
    variant === 'primary' ? 'btn-primary' : variant === 'outline' ? 'btn-outline' : `btn-${variant}`,
    tone === 'danger' ? 'btn-danger' : '',
    size === 'sm' ? 'btn-sm' : '',
    className,
  ].join(' ')
  return (
    <button className={cls} disabled={busy || rest.disabled} {...rest}>
      {busy ? <Icon name="loading" size={18} loop /> : icon ? <Icon name={icon} size={18} /> : null}
      {children}
    </button>
  )
}
