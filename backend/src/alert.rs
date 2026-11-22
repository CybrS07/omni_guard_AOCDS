//! System alert: a Windows message box that asks the user what to do with a dangerous download.
//! It blocks until the person answers, so call it from its own thread.
//! (The same choice can also be made from the dashboard's Downloads page - whichever comes first wins.)

use crate::util::powershell;

/// `Some(true)` = Yes / allow, `Some(false)` = No / remove, `None` = no dialog could be shown.
pub fn ask_yes_no(title: &str, text: &str) -> Option<bool> {
    if !cfg!(windows) {
        return None;
    }
    // Text goes in through environment variables so file names can never run as commands.
    // If the agent runs as a service (no desktop of its own) ServiceNotification shows the box
    // on the logged-in user's screen.
    let script = r#"Add-Type -AssemblyName System.Windows.Forms
$o=[System.Windows.Forms.MessageBoxOptions]::DefaultDesktopOnly
if(-not [Environment]::UserInteractive){$o=[System.Windows.Forms.MessageBoxOptions]::ServiceNotification}
[System.Windows.Forms.MessageBox]::Show($env:A_TEXT,$env:A_TITLE,[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Warning,[System.Windows.Forms.MessageBoxDefaultButton]::Button2,$o)"#;
    let out = powershell(script, &[("A_TITLE", title), ("A_TEXT", text)], 3600)?;
    match out.stdout.trim() {
        "Yes" => Some(true),
        "No" => Some(false),
        _ => None,
    }
}
