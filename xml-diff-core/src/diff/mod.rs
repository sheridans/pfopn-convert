//! Core XML tree diffing.

pub mod engine;
pub mod result;

pub use engine::{diff, diff_with_options, DiffOptions};
pub use result::DiffEntry;
