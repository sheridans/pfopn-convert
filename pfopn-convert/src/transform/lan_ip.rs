use std::net::Ipv4Addr;

use anyhow::{bail, Result};
use xml_diff_core::XmlNode;

/// Rewrite the LAN interface IP address and update every reference to it
/// throughout the config tree.
///
/// This implements the `--lan-ip` CLI flag. When migrating a config to new
/// hardware, the LAN subnet often changes (e.g. 10.1.10.0/24 to
/// 192.168.1.0/24). Simply changing `<interfaces><lan><ipaddr>` would leave
/// stale references in DHCP ranges, static routes, gateway entries, etc.
///
/// The update is applied in three passes:
/// 1. **`set_lan_ip`** -- write the new IP into `<interfaces><lan><ipaddr>`.
/// 2. **`remap_lan_dhcp_ipv4`** -- walk `<dhcpd><lan>` and remap any IPv4
///    address that falls within the old LAN subnet into the new subnet,
///    preserving host bits (e.g. .100 stays .100).
/// 3. **`replace_exact_ip_text`** -- sweep the entire tree for text nodes
///    that exactly match the old LAN IP and replace them (catches gateways,
///    static routes, and other stray references).
///
/// Before making changes, `ensure_no_conflict` checks that no other interface
/// already uses the requested IP. If the old and new IPs are identical, the
/// function is a no-op.
pub fn apply(root: &mut XmlNode, new_lan_ip: &str) -> Result<()> {
    let new_ip: Ipv4Addr = new_lan_ip
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --lan-ip value: {new_lan_ip}"))?;

    let interfaces = root
        .get_child("interfaces")
        .ok_or_else(|| anyhow::anyhow!("missing interfaces section"))?;
    let lan = interfaces
        .get_child("lan")
        .ok_or_else(|| anyhow::anyhow!("missing interfaces.lan section"))?;
    let old_ip_str = lan
        .get_text(&["ipaddr"])
        .ok_or_else(|| anyhow::anyhow!("missing interfaces.lan.ipaddr"))?
        .trim()
        .to_string();
    let old_ip: Ipv4Addr = old_ip_str
        .parse()
        .map_err(|_| anyhow::anyhow!("interfaces.lan.ipaddr is not IPv4: {old_ip_str}"))?;
    if old_ip == new_ip {
        return Ok(());
    }
    let prefix = lan
        .get_text(&["subnet"])
        .and_then(|s| s.trim().parse::<u8>().ok())
        .unwrap_or(24);

    ensure_no_conflict(root, new_ip)?;
    set_lan_ip(root, new_ip);
    remap_lan_dhcp_ipv4(root, old_ip, new_ip, prefix);
    replace_exact_ip_text(
        root,
        old_ip.to_string().as_str(),
        new_ip.to_string().as_str(),
    );
    Ok(())
}

/// Bail if any non-LAN interface already uses `new_ip` as its `<ipaddr>`.
///
/// Prevents silently creating a duplicate-IP situation that would break
/// routing on the target box.
fn ensure_no_conflict(root: &XmlNode, new_ip: Ipv4Addr) -> Result<()> {
    let new_ip_s = new_ip.to_string();
    let Some(interfaces) = root.get_child("interfaces") else {
        return Ok(());
    };
    for iface in &interfaces.children {
        if iface.tag == "lan" {
            continue;
        }
        if iface.get_text(&["ipaddr"]).map(str::trim) == Some(new_ip_s.as_str()) {
            bail!(
                "--lan-ip conflicts with existing interface {}.ipaddr={}",
                iface.tag,
                new_ip_s
            );
        }
    }
    Ok(())
}

/// Write `new_ip` into `<interfaces><lan><ipaddr>`.
fn set_lan_ip(root: &mut XmlNode, new_ip: Ipv4Addr) {
    let Some(interfaces) = child_mut(root, "interfaces") else {
        return;
    };
    let Some(lan) = child_mut(interfaces, "lan") else {
        return;
    };
    set_or_insert_text_child(lan, "ipaddr", &new_ip.to_string());
}

/// Remap all IPv4 addresses within `<dhcpd><lan>` from the old subnet to the
/// new one, preserving host bits.
///
/// For example, if the old LAN is 10.1.10.0/24 and the new one is
/// 192.168.1.0/24, a DHCP range start of 10.1.10.100 becomes 192.168.1.100.
fn remap_lan_dhcp_ipv4(root: &mut XmlNode, old_ip: Ipv4Addr, new_ip: Ipv4Addr, prefix: u8) {
    let Some(dhcpd) = child_mut(root, "dhcpd") else {
        return;
    };
    let Some(lan) = child_mut(dhcpd, "lan") else {
        return;
    };
    remap_ipv4_in_subtree(lan, old_ip, new_ip, prefix);
}

/// Recursively walk a subtree, remapping any text node that parses as an IPv4
/// address within the old subnet.
fn remap_ipv4_in_subtree(node: &mut XmlNode, old_ip: Ipv4Addr, new_ip: Ipv4Addr, prefix: u8) {
    if let Some(text) = node.text.clone() {
        if let Some(remapped) = remap_if_in_old_subnet(text.trim(), old_ip, new_ip, prefix) {
            node.text = Some(remapped);
        }
    }
    for child in &mut node.children {
        remap_ipv4_in_subtree(child, old_ip, new_ip, prefix);
    }
}

/// If `value` is an IPv4 address within the old LAN subnet, return it
/// remapped into the new subnet with the same host portion. Otherwise return
/// `None`.
///
/// For example, with old_ip=10.1.10.1/24 and new_ip=192.168.1.1/24:
///   "10.1.10.200" -> Some("192.168.1.200")
///   "172.16.0.5"  -> None  (not in the old subnet)
///   "hello"       -> None  (not an IP address)
fn remap_if_in_old_subnet(
    value: &str,
    old_ip: Ipv4Addr,
    new_ip: Ipv4Addr,
    prefix: u8,
) -> Option<String> {
    let addr: Ipv4Addr = value.parse().ok()?;
    let old_net = network(old_ip, prefix)?;
    if (u32::from(addr) & mask(prefix)?) != old_net {
        return None;
    }
    let host_bits = !mask(prefix)?;
    let host = u32::from(addr) & host_bits;
    let new_net = network(new_ip, prefix)?;
    Some(Ipv4Addr::from(new_net | host).to_string())
}

/// Recursively replace any text node whose trimmed value exactly matches
/// `old_ip` with `new_ip`.
///
/// This catches references outside `<dhcpd><lan>` -- static route gateways,
/// DNS forwarder entries, etc. -- that wouldn't be caught by subnet remapping.
fn replace_exact_ip_text(node: &mut XmlNode, old_ip: &str, new_ip: &str) {
    if node.text.as_deref().map(str::trim) == Some(old_ip) {
        node.text = Some(new_ip.to_string());
    }
    for child in &mut node.children {
        replace_exact_ip_text(child, old_ip, new_ip);
    }
}

/// Compute the network address (host bits zeroed) for the given IP and prefix.
fn network(ip: Ipv4Addr, prefix: u8) -> Option<u32> {
    Some(u32::from(ip) & mask(prefix)?)
}

/// Return the subnet mask as a `u32` for a CIDR prefix length (0..=32).
///
/// Returns `None` for invalid prefix lengths (> 32).
fn mask(prefix: u8) -> Option<u32> {
    if prefix > 32 {
        return None;
    }
    if prefix == 0 {
        return Some(0);
    }
    Some(u32::MAX << (32 - prefix))
}

/// Return a mutable reference to the first child with the given tag.
fn child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    let idx = node.children.iter().position(|c| c.tag == tag)?;
    Some(&mut node.children[idx])
}

/// Set the text of an existing `<tag>` child, or create one if it doesn't exist.
fn set_or_insert_text_child(node: &mut XmlNode, tag: &str, value: &str) {
    if let Some(child) = node.children.iter_mut().find(|c| c.tag == tag) {
        child.text = Some(value.to_string());
        return;
    }
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    node.children.push(child);
}

#[cfg(test)]
mod tests {
    use super::apply;
    use xml_diff_core::parse;

    #[test]
    fn updates_lan_ip_and_dhcp_lan_range_and_references() {
        let mut root = parse(
            br#"<pfsense>
                <interfaces><lan><ipaddr>10.1.10.1</ipaddr><subnet>24</subnet></lan><wan><ipaddr>198.51.100.2</ipaddr></wan></interfaces>
                <dhcpd><lan><range><from>10.1.10.100</from><to>10.1.10.200</to></range><gateway>10.1.10.1</gateway></lan></dhcpd>
                <staticroutes><route><gateway>10.1.10.1</gateway></route></staticroutes>
            </pfsense>"#,
        )
        .expect("parse");

        apply(&mut root, "192.168.1.1").expect("apply");

        assert_eq!(
            root.get_text(&["interfaces", "lan", "ipaddr"]),
            Some("192.168.1.1")
        );
        assert_eq!(
            root.get_text(&["dhcpd", "lan", "range", "from"]),
            Some("192.168.1.100")
        );
        assert_eq!(
            root.get_text(&["dhcpd", "lan", "range", "to"]),
            Some("192.168.1.200")
        );
        assert_eq!(
            root.get_text(&["dhcpd", "lan", "gateway"]),
            Some("192.168.1.1")
        );
        assert_eq!(
            root.get_text(&["staticroutes", "route", "gateway"]),
            Some("192.168.1.1")
        );
    }
}
