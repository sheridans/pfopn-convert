# xml-diff-core

A fast, general-purpose XML tree parsing and diff library for Rust.

## Features

- Parse XML into a deterministic tree model (`XmlNode`)
- Write XML back from the tree model
- Diff two XML trees with path-aware structured results
- Text, summary, and JSON formatting helpers
- Optional diff tuning (`ignore_paths`, `key_fields`, `max_depth`)

## Quick Start

```rust
use xml_diff_core::{diff, format_text, parse_file};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let left = parse_file("before.xml".as_ref())?;
    let right = parse_file("after.xml".as_ref())?;

    let entries = diff(&left, &right);
    println!("{}", format_text(&entries));
    Ok(())
}
```

## Core API

- `parse`, `parse_file`
- `write`, `write_file`
- `diff`, `diff_with_options`
- `format_text`, `format_json`, `format_summary`

## Design

`xml-diff-core` is schema-agnostic. It works with any XML documents and contains no CLI or domain-specific logic.
