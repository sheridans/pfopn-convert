//! Diff output formatters.

pub mod json;
pub mod text;

pub use json::format_json;
pub use text::{format_summary, format_text};
