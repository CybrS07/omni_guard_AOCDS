import UseAnimations from 'react-useanimations'
import activity from 'react-useanimations/lib/activity'
import layout from 'react-useanimations/lib/layout'
import shield from 'react-useanimations/lib/shield'
import fileText from 'react-useanimations/lib/fileText'
import cpu from 'react-useanimations/lib/cpu'
import wifi from 'react-useanimations/lib/wifi'
import globe from 'react-useanimations/lib/globe'
import terminal from 'react-useanimations/lib/terminal'
import database from 'react-useanimations/lib/database'
import alertTriangle from 'react-useanimations/lib/alertTriangle'
import plusCircle from 'react-useanimations/lib/plusCircle'
import trash from 'react-useanimations/lib/trash2'
import refresh from 'react-useanimations/lib/refresh'
import lock from 'react-useanimations/lib/lock'
import radio from 'react-useanimations/lib/radio'
import check from 'react-useanimations/lib/checkmark'
import loading from 'react-useanimations/lib/loading'
import server from 'react-useanimations/lib/server'
import power from 'react-useanimations/lib/power'
import folder from 'react-useanimations/lib/folder'
import sun from 'react-useanimations/lib/sun'
import moon from 'react-useanimations/lib/moon'
import box from 'react-useanimations/lib/box'
import download from 'react-useanimations/lib/download'

// useAnimations icons: https://useanimations.com/#icons
// Each icon plays its own built-in interaction (hover / click / loop).
const ICONS = {
  activity, layout, shield, fileText, cpu, wifi, globe, terminal, database, alertTriangle,
  plusCircle, trash, refresh, lock, radio, check, loading, server, power, folder, sun, moon, box, download,
}

/** `loop` forces a continuous animation (used for "live" indicators). */
export default function Icon({ name, size = 22, loop = false, className = '' }) {
  const animation = ICONS[name]
  if (!animation) return null
  const extra = loop ? { interaction: 'loop', autoplay: true, loop: true } : {}
  return (
    <span className={`ico ${className}`} aria-hidden="true">
      <UseAnimations animation={animation} size={size} {...extra} />
    </span>
  )
}
