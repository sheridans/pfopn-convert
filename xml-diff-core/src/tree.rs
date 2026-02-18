use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;

/// A generic XML tree node.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct XmlNode {
    /// Element tag name.
    pub tag: String,
    /// XML attributes keyed by name.
    pub attributes: BTreeMap<String, String>,
    /// Child elements.
    pub children: Vec<XmlNode>,
    /// Optional text content.
    pub text: Option<String>,
}

impl XmlNode {
    /// Create a new XML node with no attributes, children, or text.
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            attributes: BTreeMap::new(),
            children: Vec::new(),
            text: None,
        }
    }

    /// Return the first child with the provided tag.
    pub fn get_child(&self, tag: &str) -> Option<&XmlNode> {
        self.children.iter().find(|child| child.tag == tag)
    }

    /// Return all children with the provided tag.
    pub fn get_children(&self, tag: &str) -> Vec<&XmlNode> {
        self.children
            .iter()
            .filter(|child| child.tag == tag)
            .collect()
    }

    /// Walk a nested child path and return terminal node text if found.
    pub fn get_text<'a>(&'a self, path: &[&str]) -> Option<&'a str> {
        if path.is_empty() {
            return self.text.as_deref();
        }

        let mut current = self;
        for segment in path {
            current = current.get_child(segment)?;
        }
        current.text.as_deref()
    }
}

impl Display for XmlNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "<{}", self.tag)?;
        for (key, value) in &self.attributes {
            write!(f, " {}=\"{}\"", key, value)?;
        }

        if self.children.is_empty() && self.text.is_none() {
            return write!(f, "/>");
        }

        write!(f, ">")?;
        if let Some(text) = &self.text {
            write!(f, "{}", text)?;
        }
        for child in &self.children {
            write!(f, "{}", child)?;
        }
        write!(f, "</{}>", self.tag)
    }
}

#[cfg(test)]
mod tests {
    use super::XmlNode;

    #[test]
    fn get_text_walks_nested_path() {
        let mut root = XmlNode::new("root");
        let mut parent = XmlNode::new("parent");
        let mut child = XmlNode::new("child");
        child.text = Some("value".to_string());
        parent.children.push(child);
        root.children.push(parent);

        assert_eq!(root.get_text(&["parent", "child"]), Some("value"));
    }
}
