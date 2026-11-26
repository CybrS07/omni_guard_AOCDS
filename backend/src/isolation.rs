//! The isolation folder ("quarantine") for downloads.
//! A held file is moved to <data_dir>/isolation/<id>/<name>.held so nobody can double-click it, and on Windows Everyone is denied "execute".
//! NOTHING is left behind in Downloads: an extra note file there was picked up as a new download again and again,
//! and it made folders and browsers reload. Afterwards the file is either released (gets its normal name back) or destroyed.
//! This is quarantine, not a virtual machine: the file never runs while it is held.

use crate::util::run; // runs a command and gives back its output
use std::fs; // file operations
use std::path::{Path, PathBuf}; // file paths
use std::thread::sleep; // waits between retries
use std::time::Duration; // lengths of time

const EVERYONE: &str = "*S-1-1-0"; // the well-known Windows id of "Everyone", it works in every language
const NOTE_SUFFIX: &str = ".soc-pending.txt"; // note files that older versions left in Downloads

/// True for the leftover note files of older versions (they must be ignored and cleaned up).
pub fn is_leftover_note(path: &Path) -> bool {
    path.to_string_lossy().contains(NOTE_SUFFIX) // "x.png.soc-pending.txt.soc-pending.txt" also counts
}

/// Deletes leftover note files in one folder. Returns how many were removed.
pub fn clean_leftovers(dir: &Path) -> usize {
    let Ok(rd) = fs::read_dir(dir) else { return 0 }; // unreadable folder: nothing to do
    let mut n = 0; // counter
    for e in rd.flatten() {
        let p = e.path(); // one entry of the folder
        if p.is_file() && is_leftover_note(&p) && fs::remove_file(&p).is_ok() {
            n += 1; // one more removed
        }
    }
    n
}

/// Moves `src` into its own isolation folder and returns the new (held) path.
pub fn isolate(root: &Path, id: &str, src: &Path) -> Result<PathBuf, String> {
    let dir = root.join(id); // one folder per download
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create isolation folder: {e}"))?; // make sure it exists
    let name = src.file_name().ok_or("file has no name")?.to_string_lossy().into_owned(); // the original file name
    let held = dir.join(format!("{name}.held")); // the held file cannot be opened by double-click
    move_file(src, &held)?; // move it away from Downloads
    set_execute_denied(&held, true); // on Windows: nobody may execute it
    Ok(held)
}

/// Puts a held file back at `original` with its normal name (or "name (2).ext" if that name is taken). Returns where it ended up.
pub fn release(held: &Path, original: &Path) -> Result<PathBuf, String> {
    set_execute_denied(held, false); // allow execute again
    let mut dest = original.to_path_buf(); // first try the original name
    let mut n = 2; // number used when the name is taken
    while dest.exists() {
        let stem = original.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(); // name without extension
        let ext = original.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default(); // extension with dot
        dest = original.with_file_name(format!("{stem} ({n}){ext}")); // "name (2).ext"
        n += 1;
    }
    move_file(held, &dest)?; // back to the normal place and name
    remove_hold_dir(held); // remove the empty isolation folder
    Ok(dest)
}

/// Deletes a held file completely, together with its folder.
pub fn destroy(held: &Path) -> Result<(), String> {
    set_execute_denied(held, false); // permissions must allow the delete
    if held.exists() {
        fs::remove_file(held).map_err(|e| format!("cannot delete: {e}"))?; // delete the file
    }
    remove_hold_dir(held); // delete the empty folder
    Ok(())
}

/// Removes the isolation folder if it is empty (does nothing if something is still inside).
fn remove_hold_dir(held: &Path) {
    if let Some(dir) = held.parent() {
        let _ = fs::remove_dir(dir); // only succeeds when empty, which is what we want
    }
}

/// rename() when possible, copy + delete across drives. Retries a few times because the browser may hold the file for a moment.
fn move_file(from: &Path, to: &Path) -> Result<(), String> {
    let mut last = String::new(); // the last error text
    for _ in 0..6 {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()), // moved
            Err(_) => match fs::copy(from, to).and_then(|_| fs::remove_file(from)) {
                Ok(()) => return Ok(()), // copied and deleted the original (other drive)
                Err(e) => last = e.to_string(), // remember why
            },
        }
        sleep(Duration::from_millis(500)); // wait and try again
    }
    Err(format!("could not move {}: {last}", from.display()))
}

/// Blocks or unblocks running a file: on Windows an icacls deny for Everyone, elsewhere a plain permission change.
fn set_execute_denied(path: &Path, deny: bool) {
    if !cfg!(windows) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt; // lets us set unix permissions
            let mode = if deny { 0o600 } else { 0o644 }; // 600 = owner read/write only, 644 = normal file
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode)); // a failure is not fatal
        }
        return;
    }
    let p = path.to_string_lossy(); // the path as text for the command
    if deny {
        run("icacls", &[p.as_ref(), "/deny", &format!("{EVERYONE}:(X)")], 15); // deny execute
    } else {
        run("icacls", &[p.as_ref(), "/remove:d", EVERYONE], 15); // remove the deny rule
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leftover_notes_are_recognised_even_when_stacked() {
        assert!(is_leftover_note(Path::new("C:/Users/a/Downloads/favicon.png.soc-pending.txt")));
        assert!(is_leftover_note(Path::new("favicon.png.soc-pending.txt.soc-pending.txt.soc-pending.txt")));
        assert!(!is_leftover_note(Path::new("favicon.png")));
    }

    #[test]
    fn isolate_then_release_gives_the_normal_file_back_and_leaves_nothing_behind() {
        let base = std::env::temp_dir().join(format!("iso-test-{}", std::process::id())); // a private test folder
        let (downloads, root) = (base.join("Downloads"), base.join("iso"));
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("favicon.png");
        fs::write(&file, b"png bytes").unwrap();
        let held = isolate(&root, "abc", &file).unwrap();
        assert!(!file.exists(), "the file left Downloads");
        assert_eq!(fs::read_dir(&downloads).unwrap().count(), 0, "no note file is left in Downloads");
        assert!(held.to_string_lossy().ends_with(".held"));
        let back = release(&held, &file).unwrap();
        assert_eq!(back, file, "the normal name is back");
        assert_eq!(fs::read(&back).unwrap(), b"png bytes");
        assert!(!root.join("abc").exists(), "the isolation folder is gone");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn destroy_deletes_the_file_and_its_folder() {
        let base = std::env::temp_dir().join(format!("iso-test2-{}", std::process::id()));
        let (downloads, root) = (base.join("Downloads"), base.join("iso"));
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("bad.exe");
        fs::write(&file, b"MZ").unwrap();
        let held = isolate(&root, "xyz", &file).unwrap();
        destroy(&held).unwrap();
        assert!(!held.exists() && !root.join("xyz").exists() && !file.exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn clean_leftovers_removes_only_note_files() {
        let dir = std::env::temp_dir().join(format!("iso-test3-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.png.soc-pending.txt.soc-pending.txt"), b"x").unwrap();
        fs::write(dir.join("keep.txt"), b"x").unwrap();
        assert_eq!(clean_leftovers(&dir), 1);
        assert!(dir.join("keep.txt").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
