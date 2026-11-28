//! Archive and tree handling: reading a package archive, checking symlinks, copying trees.

/// Written into a store directory once its content is final.
pub(crate) const STORE_MARKER: &str = ".portalis-complete";

mod collect;
mod copy;
mod paths;
mod stream;
mod unpack;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use paths::close_absolute_links;
pub(crate) use paths::{close_absolute_links_at, validate_tree_links};
pub(crate) use stream::{create_private, decompress_to, member_modes, private_dir, read_member};

pub(crate) use collect::{
    collect_dirs, collect_files, digest_of, marker_digest, marker_recipe, marker_text, marker_tree,
    normalised_dir_mode, tree_digest, validate_source_symlinks,
};
pub(crate) use copy::copy_tree;
pub(crate) use unpack::unpack_archive;

#[cfg(test)]
use stream::{copy_bounded, DeadlineReader};
