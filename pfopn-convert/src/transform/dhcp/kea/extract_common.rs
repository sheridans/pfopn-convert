use xml_diff_core::XmlNode;

/// Check if DHCP is enabled on an ISC DHCP interface section.
///
/// ISC DHCP uses multiple ways to indicate if DHCP is enabled on an interface:
/// - `<disabled>` element (presence or truthy value = disabled)
/// - `<enable>` element (empty or truthy = enabled)
/// - `<enabled>` element (truthy = enabled)
///
/// Returns `true` if DHCP is enabled, `false` if explicitly disabled.
/// Default is `true` (enabled) if no flags are present.
pub(crate) fn isc_iface_enabled(iface: &XmlNode) -> bool {
    if let Some(disabled) = iface.get_text(&["disabled"]) {
        if isc_truthy(disabled) || disabled.trim().is_empty() {
            return false;
        }
    }
    if let Some(enable_node) = iface.get_child("enable") {
        let value = enable_node.text.as_deref().unwrap_or("").trim();
        return value.is_empty() || isc_truthy(value);
    }
    if let Some(enabled) = iface.get_text(&["enabled"]) {
        return isc_truthy(enabled);
    }
    true
}

/// Check if a string represents a boolean true value in ISC DHCP config.
///
/// Recognizes: "1", "yes", "true", "enabled", "on" (case-insensitive).
fn isc_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "enabled" | "on"
    )
}
