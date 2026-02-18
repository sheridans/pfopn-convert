use serde::Serialize;

use crate::XmlNode;

/// A single diff outcome for a node path.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type")]
pub enum DiffEntry {
    /// Node exists in both with identical content.
    Identical { path: String },
    /// Node exists in both but text/attributes differ.
    Modified {
        path: String,
        left: String,
        right: String,
    },
    /// Node only in the left input.
    OnlyLeft { path: String, node: XmlNode },
    /// Node only in the right input.
    OnlyRight { path: String, node: XmlNode },
    /// Structural mismatch (for example, node tag mismatch).
    Structural { path: String, description: String },
}
