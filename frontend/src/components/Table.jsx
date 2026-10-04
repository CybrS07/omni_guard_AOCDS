export default function Table({ columns, rows }) {
  return (
    <table className="table">
      <thead>
        <tr>{columns.map((c) => <th key={c.key}>{c.label}</th>)}</tr>
      </thead>
      <tbody>
        {rows.length === 0 && <tr><td colSpan={columns.length} className="muted">No data</td></tr>}
        {rows.map((r, i) => (
          <tr key={i}>{columns.map((c) => <td key={c.key}>{r[c.key]}</td>)}</tr>
        ))}
      </tbody>
    </table>
  )
}
