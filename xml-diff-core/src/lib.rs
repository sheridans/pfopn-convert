//! Generic XML parsing and writing primitives used by higher-level tools.

pub mod diff;
pub mod format;
pub mod parser;
pub mod tree;
pub mod writer;

pub use diff::{diff, diff_with_options, DiffEntry, DiffOptions};
pub use format::{format_json, format_summary, format_text};
pub use parser::{parse, parse_file, ParseError};
pub use tree::XmlNode;
pub use writer::{write, write_file, WriteError};
