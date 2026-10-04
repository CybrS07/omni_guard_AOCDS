export default function Badge({ level = 'info' }) {
  return <span className={`badge ${level}`}>{level}</span>
}
