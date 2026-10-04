export default function Settings() {
  return (
    <>
      <h1>Settings</h1>
      <div className="card form">
        <label>Alert email <input type="email" placeholder="you@example.com" /></label>
        <label>Voice alerts <input type="checkbox" /></label>
        <label>Folder to watch <input placeholder="C:\Users\...\Downloads" /></label>
        <button>Save</button>
      </div>
    </>
  )
}
