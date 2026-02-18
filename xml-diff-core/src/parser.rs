use std::fs;
use std::path::Path;

use quick_xml::events::Event;
use quick_xml::name::QName;
use quick_xml::Reader;
use thiserror::Error;

use crate::tree::XmlNode;

/// Errors that can occur while parsing XML into an [`XmlNode`] tree.
#[derive(Debug, Error)]
pub enum ParseError {
    /// Input XML could not be decoded or tokenized.
    #[error("failed to parse XML: {0}")]
    Xml(#[from] quick_xml::Error),
    /// Input bytes were not valid UTF-8 for tag/attribute/text extraction.
    #[error("invalid UTF-8 while parsing XML: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    /// Failed to decode text entity or bytes.
    #[error("failed to decode XML text: {0}")]
    Escape(#[from] quick_xml::escape::EscapeError),
    /// Failed to read input file.
    #[error("failed to read XML file: {0}")]
    Io(#[from] std::io::Error),
    /// Structural issue in XML document.
    #[error("malformed XML: {0}")]
    Malformed(String),
}

/// Parse XML bytes into an [`XmlNode`] tree.
pub fn parse(xml: &[u8]) -> Result<XmlNode, ParseError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut buf = Vec::new();
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root: Option<XmlNode> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let node = build_node_start(&e, &reader)?;
                stack.push(node);
            }
            Event::Empty(e) => {
                let node = build_node_start(&e, &reader)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.is_none() {
                    root = Some(node);
                } else {
                    return Err(ParseError::Malformed(
                        "multiple top-level elements found".to_string(),
                    ));
                }
            }
            Event::Text(e) => {
                if let Some(current) = stack.last_mut() {
                    let text = e.unescape()?.into_owned();
                    if !text.trim().is_empty() {
                        match &mut current.text {
                            Some(existing) => existing.push_str(&text),
                            None => current.text = Some(text),
                        }
                    }
                }
            }
            Event::CData(e) => {
                if let Some(current) = stack.last_mut() {
                    let text = std::str::from_utf8(e.as_ref())?.to_string();
                    if !text.trim().is_empty() {
                        match &mut current.text {
                            Some(existing) => existing.push_str(&text),
                            None => current.text = Some(text),
                        }
                    }
                }
            }
            Event::End(_) => {
                let node = stack.pop().ok_or_else(|| {
                    ParseError::Malformed("encountered closing tag without open tag".to_string())
                })?;

                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.is_none() {
                    root = Some(node);
                } else {
                    return Err(ParseError::Malformed(
                        "multiple top-level elements found".to_string(),
                    ));
                }
            }
            Event::Eof => break,
            Event::Decl(_) | Event::PI(_) | Event::DocType(_) | Event::Comment(_) => {}
        }
        buf.clear();
    }

    if !stack.is_empty() {
        return Err(ParseError::Malformed(
            "unclosed element(s) at end of document".to_string(),
        ));
    }

    root.ok_or_else(|| ParseError::Malformed("no root element found".to_string()))
}

/// Parse an XML file into an [`XmlNode`] tree.
pub fn parse_file(path: &Path) -> Result<XmlNode, ParseError> {
    let bytes = fs::read(path)?;
    parse(&bytes)
}

fn build_node_start(
    e: &quick_xml::events::BytesStart<'_>,
    reader: &Reader<&[u8]>,
) -> Result<XmlNode, ParseError> {
    let tag = qname_to_string(e.name())?;
    let mut node = XmlNode::new(tag);

    for attr in e.attributes() {
        let attr = attr.map_err(quick_xml::Error::from)?;
        let key = qname_to_string(attr.key)?;
        let value = attr
            .decode_and_unescape_value(reader.decoder())?
            .into_owned();
        node.attributes.insert(key, value);
    }

    Ok(node)
}

fn qname_to_string(name: QName<'_>) -> Result<String, ParseError> {
    Ok(std::str::from_utf8(name.as_ref())?.to_string())
}
