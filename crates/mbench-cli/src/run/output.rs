//! Output-path resolution, alias validation, raw serial persistence, and atomic capture replacement.

use std::{
    collections::VecDeque,
    ffi::OsString,
    fs, io,
    io::{LineWriter, Write},
    path::{Component, Path, PathBuf},
};

use mbench_core::wire::{AttemptRecord, RawAttemptStart};

enum PathStep {
    Prefix(OsString),
    Root,
    Cur,
    Parent,
    Normal(OsString),
}

fn push_components_front(queue: &mut VecDeque<PathStep>, path: &Path) {
    let steps: Vec<PathStep> = path
        .components()
        .map(|comp| match comp {
            Component::Prefix(p) => PathStep::Prefix(p.as_os_str().to_os_string()),
            Component::RootDir => PathStep::Root,
            Component::CurDir => PathStep::Cur,
            Component::ParentDir => PathStep::Parent,
            Component::Normal(s) => PathStep::Normal(s.to_os_string()),
        })
        .collect();
    for step in steps.into_iter().rev() {
        queue.push_front(step);
    }
}

fn ensure_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    Ok(())
}

/// Resolves symlinks across existing prefixes and dangling/chained leaves before directory creation.
pub(super) fn resolve_logical_target_path(path: &Path) -> Result<PathBuf, String> {
    const MAX_SYMLINK_HOPS: usize = 40;

    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to resolve current directory: {e}"))?
            .join(path)
    };

    let mut queue = VecDeque::new();
    push_components_front(&mut queue, &abs);
    let mut resolved = PathBuf::new();
    let mut hops = 0usize;

    while let Some(step) = queue.pop_front() {
        match step {
            PathStep::Prefix(p) => resolved.push(p),
            PathStep::Root => resolved.push(std::path::MAIN_SEPARATOR_STR),
            PathStep::Cur => {}
            PathStep::Parent => {
                let _ = resolved.pop();
            }
            PathStep::Normal(name) => {
                let candidate = resolved.join(&name);
                match fs::symlink_metadata(&candidate) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        hops += 1;
                        if hops > MAX_SYMLINK_HOPS {
                            return Err(format!(
                                "too many levels of symbolic links while resolving '{}'",
                                path.display()
                            ));
                        }
                        let target = fs::read_link(&candidate).map_err(|e| {
                            format!("failed to read symlink {}: {e}", candidate.display())
                        })?;
                        if target.is_absolute() {
                            resolved.clear();
                        }
                        push_components_front(&mut queue, &target);
                    }
                    Ok(_) => resolved = candidate,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => resolved = candidate,
                    Err(err) if err.kind() == io::ErrorKind::NotADirectory => {
                        // The parent validator below preserves the established ENOTDIR diagnostic.
                        resolved = candidate
                    }
                    Err(err) => {
                        return Err(format!(
                            "failed to inspect output path component '{}': {err}",
                            candidate.display()
                        ));
                    }
                }
            }
        }
    }

    Ok(resolved)
}

pub(super) fn validate_output_file_path(flag: &str, path: &Path) -> Result<(), String> {
    let raw = path.as_os_str().to_string_lossy();
    if path.as_os_str().is_empty()
        || raw.ends_with('/')
        || raw.ends_with('\\')
        || path.file_name().is_none()
    {
        return Err(format!(
            "{flag} path '{}' must include a file name",
            path.display()
        ));
    }
    let resolved = resolve_logical_target_path(path)?;
    if resolved.file_name().is_none() {
        return Err(format!(
            "{flag} path '{}' must include a file name",
            path.display()
        ));
    }
    if let Some(parent) = resolved.parent() {
        validate_parent_directory(flag, path, parent)?;
    }
    match fs::metadata(&resolved) {
        Ok(meta) if meta.is_dir() => {
            return Err(format!("{flag} path '{}' is a directory", path.display()));
        }
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to inspect {flag} path '{}': {err}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_parent_directory(flag: &str, path: &Path, parent: &Path) -> Result<(), String> {
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    for ancestor in parent.ancestors() {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        match fs::metadata(ancestor) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(format!(
                        "parent component '{}' of {flag} path '{}' is not a directory",
                        ancestor.display(),
                        path.display()
                    ));
                }
                break;
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "failed to inspect parent component '{}' of {flag} path '{}': {err}",
                    ancestor.display(),
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn paths_refer_to_same_file(a: &Path, b: &Path) -> Result<bool, String> {
    let res_a = resolve_logical_target_path(a)?;
    let res_b = resolve_logical_target_path(b)?;
    if res_a == res_b {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        if metadata_identity(&res_a, &res_b, "file identities")? {
            return Ok(true);
        }
        if let (Some(parent_a), Some(parent_b)) = (res_a.parent(), res_b.parent())
            && res_a.file_name() == res_b.file_name()
            && metadata_identity(parent_a, parent_b, "parent directories")?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(unix)]
fn metadata_identity(a: &Path, b: &Path, what: &str) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(meta_a), Ok(meta_b)) => {
            Ok(meta_a.dev() == meta_b.dev() && meta_a.ino() == meta_b.ino())
        }
        (Err(err), _) | (_, Err(err)) if err.kind() != io::ErrorKind::NotFound => {
            Err(format!("failed to compare {what}: {err}"))
        }
        _ => Ok(false),
    }
}

pub(super) struct RawLogWriter {
    pub(super) path: PathBuf,
    writer: LineWriter<fs::File>,
    pub(super) had_write_error: bool,
}

impl RawLogWriter {
    pub(super) fn create(path: &Path) -> Result<Self, String> {
        ensure_parent(path)?;
        let file = fs::File::create(path)
            .map_err(|e| format!("failed to create raw log {}: {e}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            writer: LineWriter::new(file),
            had_write_error: false,
        })
    }

    #[cfg(unix)]
    pub(super) fn same_file_as(&self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(raw_meta), Ok(other_meta)) =
            (self.writer.get_ref().metadata(), fs::metadata(path))
        {
            raw_meta.dev() == other_meta.dev() && raw_meta.ino() == other_meta.ino()
        } else {
            false
        }
    }

    #[cfg(not(unix))]
    pub(super) fn same_file_as(&self, _path: &Path) -> bool {
        false
    }

    pub(super) fn write_attempt_header(
        &mut self,
        attempt: usize,
        resume_after: Option<&str>,
    ) -> Option<String> {
        let hdr = RawAttemptStart {
            attempt,
            resume_after: resume_after.map(str::to_string),
        };
        let Ok(json) = serde_json::to_string(&hdr) else {
            return Some(String::from(
                "failed to serialize # MBENCH_RAW_ATTEMPT header",
            ));
        };
        if let Err(err) =
            writeln!(self.writer, "# MBENCH_RAW_ATTEMPT {json}").and_then(|()| self.writer.flush())
            && !self.had_write_error
        {
            self.had_write_error = true;
            return Some(format!(
                "failed to write raw log {}: {err}",
                self.path.display()
            ));
        }
        None
    }

    pub(super) fn write_attempt_footer(&mut self, record: &AttemptRecord) -> Option<String> {
        let Ok(json) = serde_json::to_string(record) else {
            return Some(String::from("failed to serialize # MBENCH_ATTEMPT footer"));
        };
        if let Err(err) =
            writeln!(self.writer, "# MBENCH_ATTEMPT {json}").and_then(|()| self.writer.flush())
            && !self.had_write_error
        {
            self.had_write_error = true;
            return Some(format!(
                "failed to write raw log {}: {err}",
                self.path.display()
            ));
        }
        None
    }

    #[cfg(test)]
    pub(super) fn write_line(&mut self, line: &str) -> Option<String> {
        if let Err(err) = writeln!(self.writer, "{line}")
            && !self.had_write_error
        {
            self.had_write_error = true;
            return Some(format!(
                "failed to write raw log {}: {err}",
                self.path.display()
            ));
        }
        None
    }

    pub(super) fn write_bytes(&mut self, bytes: &[u8]) -> Option<String> {
        if let Err(err) = self.writer.write_all(bytes)
            && !self.had_write_error
        {
            self.had_write_error = true;
            return Some(format!(
                "failed to write raw log {}: {err}",
                self.path.display()
            ));
        }
        None
    }

    pub(super) fn flush(&mut self) -> Option<String> {
        if let Err(err) = self.writer.flush()
            && !self.had_write_error
        {
            self.had_write_error = true;
            return Some(format!(
                "failed to flush raw log {}: {err}",
                self.path.display()
            ));
        }
        None
    }
}

pub(super) fn prepare_outputs(
    out_path: &Path,
    raw_log: Option<&Path>,
) -> Result<Option<RawLogWriter>, String> {
    validate_output_file_path("--out", out_path)?;
    if let Some(raw) = raw_log {
        validate_output_file_path("--raw-log", raw)?;
        if paths_refer_to_same_file(out_path, raw)? {
            return Err(alias_error(out_path, raw));
        }
    }

    ensure_parent(out_path)?;

    let Some(raw) = raw_log else {
        return Ok(None);
    };

    ensure_parent(raw)?;

    if paths_refer_to_same_file(out_path, raw)? {
        return Err(alias_error(out_path, raw));
    }

    let writer = RawLogWriter::create(raw)?;
    if paths_refer_to_same_file(out_path, &writer.path)? || writer.same_file_as(out_path) {
        return Err(alias_error(out_path, &writer.path));
    }
    Ok(Some(writer))
}

fn alias_error(out_path: &Path, raw_path: &Path) -> String {
    format!(
        "--out ('{}') and --raw-log ('{}') must not refer to the same file",
        out_path.display(),
        raw_path.display()
    )
}

pub(super) fn save_outputs_independently(
    out_path: &Path,
    out_content: Option<&str>,
    raw_writer: &mut Option<RawLogWriter>,
) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(content) = out_content {
        let alias_err = raw_writer.as_ref().and_then(|writer| {
            match paths_refer_to_same_file(out_path, &writer.path) {
                Ok(aliased) if aliased || writer.same_file_as(out_path) => Some(format!(
                    "refusing to overwrite raw log '{}' through aliased --out path '{}'",
                    writer.path.display(),
                    out_path.display()
                )),
                Ok(_) => None,
                Err(err) => Some(format!(
                    "refusing to overwrite output because file identity could not be verified: {err}"
                )),
            }
        });
        let write_res = if let Some(err) = alias_err {
            Err(err)
        } else {
            atomic_write(out_path, content.as_bytes()).map(|()| {
                eprintln!("[mbench-cli] saved {}", out_path.display());
            })
        };
        if let Err(err) = write_res {
            eprintln!("[mbench-cli] warning: {err}");
            errors.push(err);
        }
    }
    if let Some(writer) = raw_writer {
        if let Some(err) = writer.flush() {
            eprintln!("[mbench-cli] warning: {err}");
            errors.push(err);
        } else if !writer.had_write_error {
            eprintln!("[mbench-cli] saved raw log {}", writer.path.display());
        }
    }
    errors
}

/// Replaces a file only after a sibling temporary file was completely written and synced.
pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let target = resolve_logical_target_path(path)?;
    ensure_parent(&target)?;
    let temporary = temporary_path(&target)?;
    let result = (|| -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| {
                format!(
                    "failed to create temporary output {}: {e}",
                    temporary.display()
                )
            })?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("failed to write {}: {e}", temporary.display()))?;
        drop(file);
        replace_file(&temporary, &target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Atomically moves a completed sibling artifact over the requested output path.
pub(super) fn replace_file(temporary: &Path, path: &Path) -> Result<(), String> {
    fs::rename(temporary, path).map_err(|e| {
        format!(
            "failed to replace {} with {}: {e}",
            path.display(),
            temporary.display()
        )
    })
}

pub(super) fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| format!("output path '{}' must include a file name", path.display()))?;
    Ok(parent.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        unique_suffix()
    )))
}

fn unique_suffix() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    time ^ u128::from(count)
}
