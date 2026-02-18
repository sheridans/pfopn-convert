use std::fs;
use std::path::Path;

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use thiserror::Error;

use crate::tree::XmlNode;

/// Errors that can occur while writing XML from an [`XmlNode`] tree.
#[derive(Debug, Error)]
pub enum WriteError {
    /// Failed to serialize XML bytes.
    #[error("failed to write XML: {0}")]
    Xml(#[from] quick_xml::Error),
    /// Failed to write output file.
    #[error("failed to write XML file: {0}")]
    Io(#[from] std::io::Error),
}

/// Serialize an [`XmlNode`] tree into XML bytes.
pub fn write(node: &XmlNode) -> Result<Vec<u8>, WriteError> {
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
    write_node(&mut writer, node)?;
    Ok(writer.into_inner())
}

/// Serialize an [`XmlNode`] tree and write it to `path`.
pub fn write_file(node: &XmlNode, path: &Path) -> Result<(), WriteError> {
    let bytes = write(node)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn write_node(writer: &mut Writer<Vec<u8>>, node: &XmlNode) -> Result<(), quick_xml::Error> {
    let mut start = BytesStart::new(node.tag.as_str());

    for (key, value) in &node.attributes {
        start.push_attribute((key.as_str(), value.as_str()));
    }

    if node.children.is_empty() && node.text.is_none() {
        writer.write_event(Event::Empty(start))?;
        return Ok(());
    }

    writer.write_event(Event::Start(start))?;

    if let Some(text) = &node.text {
        writer.write_event(Event::Text(BytesText::new(text)))?;
    }

    for child in &node.children {
        write_node(writer, child)?;
    }

    writer.write_event(Event::End(BytesEnd::new(node.tag.as_str())))?;
    Ok(())
}
