//! Step 3: the isolation space ("temp space around the file").
//! A new download is moved out of Downloads/Desktop into its own private folder
//! (<data_dir>/isolation/<id>/), renamed to *.held so it cannot be double-clicked, and on Windows
//! Everyone is denied "execute" on it. A small note file is left where the download was.
//! Afterwards the file is either released (moved back) or destroyed (deleted for good).
//! This is quarantine, not a virtual machine: the file never runs while it is held.

use crate::util::run;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

const EVERYONE: &str = "*S-1-1-0"; // well-known SID, works on every Windows language

/// Builds the path of the note file that is left where a download was, named after the original file.
pub fn placeholder(original: &Path) -> PathBuf {
    let mut s = original.as_os_str().to_owned();
    s.push(".soc-pending.txt");
    PathBuf::from(s)
}

/// Move `src` into the isolation folder. Returns the new (held) path.
pub fn isolate(root: &Path, id: &str, src: &Path) -> Result<PathBuf, String> {
    let dir = root.join(id);
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create isolation folder: {e}"))?;
    let name = src.file_name().ok_or("file has no name")?.to_string_lossy().into_owned();
    let held = dir.join(format!("{name}.held"));
    move_file(src, &held)?;
    set_execute_denied(&held, true);
    let _ = fs::write(
        placeholder(src),
        format!("Omni Guard AOCDS is checking \"{name}\".\r\nIt is held in isolation until the check is finished.\r\nThis note disappears when the file is released or removed.\r\n"),
    );
    Ok(held)
}

/// Put a held file back at `original` (or next to it if that name is taken). Returns where it ended up.
pub fn release(held: &Path, original: &Path) -> Result<PathBuf, String> {
    set_execute_denied(held, false);
    let mut dest = original.to_path_buf();
    let mut n = 2;
    while dest.exists() {
        let stem = original.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let ext = original.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
        dest = original.with_file_name(format!("{stem} ({n}){ext}"));
        n += 1;
    }
    move_file(held, &dest)?;
    let _ = fs::remove_file(placeholder(original));
    remove_hold_dir(held);
    Ok(dest)
}

/// Delete a held file completely, together with its folder and the note.
pub fn destroy(held: &Path, original: &Path) -> Result<(), String> {
    set_execute_denied(held, false);
    if held.exists() {
        fs::remove_file(held).map_err(|e| format!("cannot delete: {e}"))?;
    }
    let _ = fs::remove_file(placeholder(original));
    remove_hold_dir(held);
    Ok(())
}

/// Removes the holding folder if it is empty; does nothing if files are still inside.
fn remove_hold_dir(held: &Path) {
    if let Some(dir) = held.parent() {
        let _ = fs::remove_dir(dir); // only succeeds when empty, which is what we want
    }
}

/// rename() when possible, copy + delete across drives. Retries a few times because the browser
/// may still be holding the file for a moment after the download finishes.
fn move_file(from: &Path, to: &Path) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..6 {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(_) => match fs::copy(from, to).and_then(|_| fs::remove_file(from)) {
                Ok(()) => return Ok(()),
                Err(e) => last = e.to_string(),
            },
        }
        sleep(Duration::from_millis(500));
    }
    Err(format!("could not move {}: {last}", from.display()))
}

/// Blocks or unblocks running a file: on Windows it sets an icacls deny for Everyone, elsewhere it changes the file permissions.
fn set_execute_denied(path: &Path, deny: bool) {
    if !cfg!(windows) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if deny { 0o600 } else { 0o644 };
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
        }
        return;
    }
    let p = path.to_string_lossy();
    if deny {
        run("icacls", &[p.as_ref(), "/deny", &format!("{EVERYONE}:(X)")], 15);
    } else {
        run("icacls", &[p.as_ref(), "/remove:d", EVERYONE], 15);
    }
}
