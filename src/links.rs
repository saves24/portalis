//! Live-tree links: creating them safely and repairing the ones a transaction missed.

#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_NEXT_LINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

mod live;
mod repair;
mod safe;

#[cfg(test)]
mod tests;

pub(crate) use live::{
    copy_into_live, ensure_live_dir, ensure_live_directory, live_path, remove_in_live,
    remove_live_directory, resolved_live_target, writable_parents,
};
pub(crate) use repair::repair_links;
pub(crate) use safe::{restore_backup, safe_symlink};
