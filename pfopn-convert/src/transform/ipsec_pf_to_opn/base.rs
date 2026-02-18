use xml_diff_core::XmlNode;

use super::util::push_text_child;

/// Create a base OPNsense IPsec configuration structure with default values.
///
/// Returns an `<IPsec>` node containing:
/// - `<general>` — Global IPsec settings (enabled, SA preferences, VPN rules)
/// - `<charon>` — strongSwan charon daemon settings (thread count, route installation)
/// - `<keyPairs>` — Container for RSA/ECDSA key pairs (initially empty)
/// - `<preSharedKeys>` — Container for PSK entries (populated during mapping)
///
/// This structure lives under `<OPNsense><IPsec>` in the output tree.
pub(super) fn base_opnsense_ipsec() -> XmlNode {
    let mut ipsec = XmlNode::new("IPsec");
    let mut general = XmlNode::new("general");
    push_text_child(&mut general, "enabled", "");
    push_text_child(&mut general, "preferred_oldsa", "0");
    push_text_child(&mut general, "disablevpnrules", "0");
    push_text_child(&mut general, "passthrough_networks", "");
    push_text_child(&mut general, "user_source", "");
    push_text_child(&mut general, "local_group", "");
    ipsec.children.push(general);

    let mut charon = XmlNode::new("charon");
    push_text_child(&mut charon, "threads", "16");
    push_text_child(&mut charon, "install_routes", "0");
    ipsec.children.push(charon);

    ipsec.children.push(XmlNode::new("keyPairs"));
    ipsec.children.push(XmlNode::new("preSharedKeys"));
    ipsec
}

/// Create a base OPNsense Swanctl configuration structure with empty containers.
///
/// Returns a `<Swanctl>` node containing empty containers for:
/// - `<Connections>` — IKE connection definitions (populated from phase1 entries)
/// - `<locals>` — Local endpoint authentication configs
/// - `<remotes>` — Remote endpoint authentication configs
/// - `<children>` — ESP child SA configs (populated from phase2 entries)
/// - `<Pools>` — Virtual IP pools (unused in pfSense → OPNsense mapping)
/// - `<VTIs>` — Virtual Tunnel Interfaces (unused in pfSense → OPNsense mapping)
/// - `<SPDs>` — Security Policy Database entries (unused in pfSense → OPNsense mapping)
///
/// This structure lives under `<OPNsense><Swanctl>` in the output tree.
pub(super) fn base_swanctl() -> XmlNode {
    let mut swanctl = XmlNode::new("Swanctl");
    swanctl.children.push(XmlNode::new("Connections"));
    swanctl.children.push(XmlNode::new("locals"));
    swanctl.children.push(XmlNode::new("remotes"));
    swanctl.children.push(XmlNode::new("children"));
    swanctl.children.push(XmlNode::new("Pools"));
    swanctl.children.push(XmlNode::new("VTIs"));
    swanctl.children.push(XmlNode::new("SPDs"));
    swanctl
}

/// Add an item to a specific container within the Swanctl structure.
///
/// Finds the child node with tag name `bucket` and appends `item` to its children.
/// Used to organize Connection, local, remote, and child entries into their respective containers.
///
/// # Example
/// ```ignore
/// push_to_swanctl(&mut swanctl, "Connections", connection_node);
/// push_to_swanctl(&mut swanctl, "locals", local_node);
/// ```
pub(super) fn push_to_swanctl(swanctl: &mut XmlNode, bucket: &str, item: XmlNode) {
    if let Some(node) = swanctl.children.iter_mut().find(|c| c.tag == bucket) {
        node.children.push(item);
    }
}

/// Add a pre-shared key entry to the IPsec preSharedKeys container.
///
/// Finds the `<preSharedKeys>` child within the IPsec node and appends the PSK entry.
pub(super) fn push_to_ipsec_psk(ipsec: &mut XmlNode, psk: XmlNode) {
    if let Some(node) = ipsec.children.iter_mut().find(|c| c.tag == "preSharedKeys") {
        node.children.push(psk);
    }
}
