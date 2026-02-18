use xml_diff_core::XmlNode;

use super::common::{push_text_child, push_unique};

/// Map OPNsense DHCRelay plugin config to pfSense relay format.
///
/// Converts OPNsense's `<OPNsense><DHCRelay>` plugin structure back to pfSense's
/// simpler `<dhcrelay>` and `<dhcp6relay>` sections.
///
/// ## Mapping Details
///
/// **Source (OPNsense plugin):**
/// ```xml
/// <OPNsense>
///   <DHCRelay>
///     <destinations uuid="dest1"><server>192.168.1.1</server></destinations>
///     <destinations uuid="dest2"><server>fd00::1</server></destinations>
///     <relays uuid="r1"><interface>lan</interface><destination>dest1</destination></relays>
///     <relays uuid="r2"><interface>opt1</interface><destination>dest1</destination></relays>
///     <relays uuid="r3"><interface>lan</interface><destination>dest2</destination></relays>
///   </DHCRelay>
/// </OPNsense>
/// ```
///
/// **Target (pfSense):**
/// ```xml
/// <dhcrelay>
///   <interface>lan,opt1</interface>
///   <server>192.168.1.1</server>
/// </dhcrelay>
/// <dhcp6relay>
///   <interface>lan</interface>
///   <server>fd00::1</server>
/// </dhcp6relay>
/// ```
///
/// The function:
/// 1. Collects all relay entries and their destination servers
/// 2. Separates IPv4 (no colons) from IPv6 (contains colons) based on server address
/// 3. Aggregates interfaces and servers for each IP version
/// 4. Creates separate relay sections for IPv4 and IPv6
pub(super) fn map_opnsense_plugin_to_pf_relay(out: &mut XmlNode, source: &XmlNode) {
    let Some(dhc) = source
        .get_child("OPNsense")
        .and_then(|n| n.get_child("DHCRelay"))
    else {
        return;
    };

    let destinations = dhc.get_children("destinations");
    let destination_server_for = |uuid: &str| -> String {
        for d in &destinations {
            if d.attributes.get("uuid").map(String::as_str) == Some(uuid) {
                return d.get_text(&["server"]).unwrap_or("").trim().to_string();
            }
        }
        String::new()
    };

    let mut ifaces_v4 = Vec::new();
    let mut ifaces_v6 = Vec::new();
    let mut servers_v4 = Vec::new();
    let mut servers_v6 = Vec::new();
    let mut enabled_v4 = false;
    let mut enabled_v6 = false;

    for r in dhc.get_children("relays") {
        let Some(iface) = r
            .get_text(&["interface"])
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            continue;
        };

        let dest_uuid = r.get_text(&["destination"]).unwrap_or("").trim();
        if dest_uuid.is_empty() {
            continue;
        }

        let server = destination_server_for(dest_uuid);
        if server.is_empty() {
            continue;
        }

        let is_v6 = server.contains(':');
        if is_v6 {
            push_unique(&mut ifaces_v6, iface.to_string());
            push_unique(&mut servers_v6, server.clone());
            if r.get_text(&["enabled"]).unwrap_or("0").trim() == "1" {
                enabled_v6 = true;
            }
        } else {
            push_unique(&mut ifaces_v4, iface.to_string());
            push_unique(&mut servers_v4, server.clone());
            if r.get_text(&["enabled"]).unwrap_or("0").trim() == "1" {
                enabled_v4 = true;
            }
        }
    }

    out.children
        .retain(|c| c.tag != "dhcrelay" && c.tag != "dhcp6relay" && c.tag != "dhcrelay6");

    if !ifaces_v4.is_empty() || !servers_v4.is_empty() {
        let mut relay = XmlNode::new("dhcrelay");
        if enabled_v4 {
            relay.children.push(XmlNode::new("enable"));
        }
        push_text_child(&mut relay, "interface", &ifaces_v4.join(","));
        push_text_child(&mut relay, "server", &servers_v4.join(","));
        out.children.push(relay);
    }

    if !ifaces_v6.is_empty() || !servers_v6.is_empty() {
        let mut relay = XmlNode::new("dhcp6relay");
        if enabled_v6 {
            relay.children.push(XmlNode::new("enable"));
        }
        push_text_child(&mut relay, "interface", &ifaces_v6.join(","));
        push_text_child(&mut relay, "server", &servers_v6.join(","));
        out.children.push(relay);
    }
}
