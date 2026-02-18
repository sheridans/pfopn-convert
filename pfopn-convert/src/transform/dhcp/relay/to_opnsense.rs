use xml_diff_core::XmlNode;

use super::common::{
    bool_to_01, ensure_child_mut, push_text_child, relay_enabled_text, synthetic_uuid,
};

/// Map pfSense DHCP relay config to OPNsense DHCRelay plugin format.
///
/// Converts pfSense's `<dhcrelay>` and `<dhcrelay6>`/`<dhcp6relay>` sections
/// into OPNsense's `<OPNsense><DHCRelay>` plugin structure.
///
/// ## Mapping Details
///
/// **Source (pfSense):**
/// ```xml
/// <dhcrelay>
///   <enable>1</enable>
///   <interface>lan,opt1</interface>
///   <server>192.168.1.1</server>
/// </dhcrelay>
/// ```
///
/// **Target (OPNsense plugin):**
/// ```xml
/// <OPNsense>
///   <DHCRelay version="1.0.1">
///     <destinations uuid="...">
///       <name>relay_destination_v4</name>
///       <server>192.168.1.1</server>
///     </destinations>
///     <relays uuid="...">
///       <enabled>1</enabled>
///       <interface>lan</interface>
///       <destination>uuid-of-destination</destination>
///     </relays>
///     <relays uuid="...">
///       <enabled>1</enabled>
///       <interface>opt1</interface>
///       <destination>uuid-of-destination</destination>
///     </relays>
///   </DHCRelay>
/// </OPNsense>
/// ```
///
/// Each pfSense relay section (IPv4 or IPv6) creates:
/// - One `<destinations>` entry for the server address
/// - One `<relays>` entry per interface, all pointing to the same destination
pub(super) fn map_pf_relay_to_opnsense_plugin(out: &mut XmlNode, source: &XmlNode) {
    let mut source_entries = Vec::new();
    if let Some(relay4) = source.get_child("dhcrelay") {
        source_entries.push((relay4, "v4"));
    }
    if let Some(relay6) = source
        .get_child("dhcp6relay")
        .or_else(|| source.get_child("dhcrelay6"))
    {
        source_entries.push((relay6, "v6"));
    }
    if source_entries.is_empty() {
        return;
    }

    let opn = ensure_child_mut(out, "OPNsense");
    opn.children.retain(|c| c.tag != "DHCRelay");

    let mut dhc = XmlNode::new("DHCRelay");
    dhc.attributes
        .insert("version".to_string(), "1.0.1".to_string());
    dhc.attributes.insert(
        "description".to_string(),
        "DHCRelay configuration".to_string(),
    );

    let mut seed = 1usize;
    for (relay, family) in source_entries {
        let interfaces: Vec<String> = relay
            .get_text(&["interface"])
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        let server = relay.get_text(&["server"]).unwrap_or("").trim().to_string();
        let enabled = bool_to_01(
            relay.get_child("enable").is_some() || relay_enabled_text(relay.get_text(&["enable"])),
        );
        if server.is_empty() || interfaces.is_empty() {
            continue;
        }

        let destination_uuid = synthetic_uuid(seed);
        seed += 1;

        let mut destination = XmlNode::new("destinations");
        destination
            .attributes
            .insert("uuid".to_string(), destination_uuid.clone());
        push_text_child(
            &mut destination,
            "name",
            &format!("relay_destination_{family}"),
        );
        push_text_child(&mut destination, "server", &server);
        dhc.children.push(destination);

        for iface in &interfaces {
            let mut relay_item = XmlNode::new("relays");
            relay_item
                .attributes
                .insert("uuid".to_string(), synthetic_uuid(seed + 100));
            seed += 1;
            push_text_child(&mut relay_item, "enabled", enabled);
            push_text_child(&mut relay_item, "interface", iface);
            push_text_child(&mut relay_item, "destination", &destination_uuid);
            push_text_child(&mut relay_item, "agent_info", "0");
            push_text_child(&mut relay_item, "carp_depend_on", "");
            dhc.children.push(relay_item);
        }
    }

    opn.children.push(dhc);
}
