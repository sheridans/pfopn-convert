use xml_diff_core::XmlNode;

use super::common::{
    bool_to_01, is_truthy, opnsense_instance_template, set_or_insert_text_child,
    source_assigned_ovpns_units, synthetic_uuid_for_id, text_or,
};

/// Map pfSense OpenVPN servers and clients to OPNsense instances.
///
/// Converts pfSense's `<openvpn-server>` and `<openvpn-client>` elements into
/// OPNsense's unified `<Instance>` structure. Each pfSense server/client becomes
/// a separate OPNsense instance distinguished by the `<role>` field.
///
/// ## Mapping Strategy
///
/// - Uses the target's existing instance as a template to ensure correct structure
/// - Assigns deterministic UUIDs based on vpnid for idempotent conversions
/// - Maps interface assignments when possible (matching count of servers to interfaces)
/// - Converts field names and structures between formats:
///   - `<disable>` (pfSense) → `<enabled>` (OPNsense, inverted logic)
///   - `<dev_mode>` → `<dev_type>`
///   - DNS/NTP servers: separate fields → comma-separated lists
///   - Push flags: separate boolean fields → comma-separated flag list
///
/// ## Round-Trip Preservation
///
/// If the pfSense config contains `<opnsense_instance_uuid>` markers (from a
/// previous OPNsense → pfSense conversion), those UUIDs are preserved to enable
/// lossless round-trip conversion.
///
/// # Arguments
///
/// * `source` - The pfSense configuration containing `<openvpn>` with servers/clients
/// * `target` - The OPNsense target template (used for default instance structure)
///
/// # Returns
///
/// An `<Instances>` node containing converted `<Instance>` elements
pub(super) fn map_pfsense_servers_to_opnsense_instances(
    source: &XmlNode,
    target: &XmlNode,
) -> XmlNode {
    let mut instances = XmlNode::new("Instances");
    let Some(openvpn) = source.get_child("openvpn") else {
        return instances;
    };

    // Get the template instance structure from the target (if it exists)
    let template = opnsense_instance_template(target);
    // Extract interface assignments (e.g., ovpns1, ovpns2) to map to vpnid
    let assigned_units = source_assigned_ovpns_units(source);
    let servers = openvpn.get_children("openvpn-server");
    let server_count = servers.len();

    for (idx, server) in servers.into_iter().enumerate() {
        // Clone the template or create a fresh instance
        let mut instance = template.clone().unwrap_or_else(|| XmlNode::new("Instance"));
        instance.tag = "Instance".to_string();

        // Try to map this server to an interface assignment to get the correct vpnid
        // If the counts match perfectly, use positional mapping
        // If there's exactly one server and one assignment, use that assignment
        let mapped_unit = if assigned_units.len() == server_count && idx < assigned_units.len() {
            Some(assigned_units[idx].as_str())
        } else if server_count == 1 && assigned_units.len() == 1 {
            Some(assigned_units[0].as_str())
        } else {
            None
        };

        // Determine the vpnid: use mapped unit from interface assignment, or fall back to pfSense's vpnid
        let vpnid = mapped_unit
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| text_or(server, &["vpnid"], "1"));

        // Preserve UUIDs from round-trip conversions, or generate deterministic ones
        let uuid = text_or(server, &["opnsense_instance_uuid"], "");
        instance.attributes.insert(
            "uuid".to_string(),
            if uuid.is_empty() {
                synthetic_uuid_for_id(vpnid.as_str(), instances.children.len())
            } else {
                uuid
            },
        );
        set_or_insert_text_child(&mut instance, "vpnid", vpnid);
        // pfSense uses <disable> (presence = disabled), OPNsense uses <enabled> (1 = enabled)
        set_or_insert_text_child(
            &mut instance,
            "enabled",
            bool_to_01(server.get_text(&["disable"]).is_none()),
        );
        set_or_insert_text_child(
            &mut instance,
            "dev_type",
            text_or(server, &["dev_mode"], "tun").to_ascii_lowercase(),
        );
        set_or_insert_text_child(
            &mut instance,
            "proto",
            text_or(server, &["protocol"], "udp").to_ascii_lowercase(),
        );
        set_or_insert_text_child(&mut instance, "port", text_or(server, &["local_port"], ""));
        set_or_insert_text_child(&mut instance, "role", "server");
        set_or_insert_text_child(
            &mut instance,
            "server",
            text_or(server, &["tunnel_network"], ""),
        );
        set_or_insert_text_child(
            &mut instance,
            "push_route",
            text_or(server, &["local_network"], ""),
        );
        set_or_insert_text_child(&mut instance, "cert", text_or(server, &["certref"], ""));
        set_or_insert_text_child(&mut instance, "ca", text_or(server, &["caref"], ""));
        set_or_insert_text_child(
            &mut instance,
            "cert_depth",
            text_or(server, &["cert_depth"], "1"),
        );
        set_or_insert_text_child(
            &mut instance,
            "topology",
            text_or(server, &["topology"], "subnet"),
        );
        set_or_insert_text_child(
            &mut instance,
            "description",
            text_or(server, &["description"], ""),
        );

        // DNS and NTP settings: pfSense uses numbered fields, OPNsense uses comma-separated lists
        let dns_values = gather_fields(
            server,
            &["dns_server1", "dns_server2", "dns_server3", "dns_server4"],
        );
        if !dns_values.is_empty() {
            set_or_insert_text_child(&mut instance, "dns_servers", dns_values.join(","));
        }
        let dns_domain = text_or(server, &["dns_domain"], "");
        if !dns_domain.is_empty() {
            set_or_insert_text_child(&mut instance, "dns_domain", dns_domain);
        }
        let dns_domain_search = text_or(server, &["dns_domain_search"], "");
        if !dns_domain_search.is_empty() {
            set_or_insert_text_child(&mut instance, "dns_domain_search", dns_domain_search);
        }
        let ntp_values = gather_fields(server, &["ntp_server1", "ntp_server2"]);
        if !ntp_values.is_empty() {
            set_or_insert_text_child(&mut instance, "ntp_servers", ntp_values.join(","));
        }

        // Custom options and push flags
        let custom_options = text_or(server, &["custom_options"], "");
        if !custom_options.is_empty() {
            set_or_insert_text_child(&mut instance, "custom_options", custom_options);
        }
        let mut push_flags: Vec<&'static str> = Vec::new();
        append_push_flag(
            &mut push_flags,
            "block-outside-dns",
            is_truthy(text_or(server, &["push_blockoutsidedns"], "0")),
        );
        let wants_register_dns = is_truthy(text_or(server, &["push_register_dns"], "0"));
        append_push_flag(&mut push_flags, "register-dns", wants_register_dns);
        if wants_register_dns {
            set_or_insert_text_child(&mut instance, "register_dns", "1");
        } else {
            set_or_insert_text_child(&mut instance, "register_dns", "0");
        }
        if !push_flags.is_empty() {
            set_or_insert_text_child(&mut instance, "various_push_flags", push_flags.join(","));
        }

        // Username/common name handling
        if let Some(username) = server
            .get_text(&["username"])
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty() && text != "0")
        {
            set_or_insert_text_child(&mut instance, "username", username);
        }
        if is_truthy(text_or(server, &["username_as_common_name"], "0")) {
            set_or_insert_text_child(&mut instance, "username_as_common_name", "1");
        }
        if is_truthy(text_or(server, &["strictusercn"], "0")) {
            set_or_insert_text_child(&mut instance, "strictusercn", "1");
        }

        // NetBIOS
        if is_truthy(text_or(server, &["netbios_enable"], "0")) {
            set_or_insert_text_child(&mut instance, "netbios_enable", "1");
        }
        if let Some(netbios_ntype) = server
            .get_text(&["netbios_ntype"])
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            set_or_insert_text_child(&mut instance, "netbios_ntype", netbios_ntype.to_string());
        }
        if let Some(netbios_scope) = server
            .get_text(&["netbios_scope"])
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            set_or_insert_text_child(&mut instance, "netbios_scope", netbios_scope.to_string());
        }

        instances.children.push(instance);
    }

    instances
}

/// Gather non-empty text values from multiple child fields.
///
/// Extracts values from the specified field names, filtering out empty or
/// whitespace-only values. Used for collecting DNS servers, NTP servers, etc.
///
/// # Example
///
/// ```ignore
/// // If node has <dns_server1>8.8.8.8</dns_server1> and <dns_server2>8.8.4.4</dns_server2>
/// let dns = gather_fields(node, &["dns_server1", "dns_server2", "dns_server3"]);
/// // Returns: vec!["8.8.8.8", "8.8.4.4"]
/// ```
fn gather_fields(node: &XmlNode, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| {
            node.get_text(&[key])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect()
}

/// Conditionally append a push flag to a list if enabled.
///
/// Used for building the comma-separated `various_push_flags` list in OPNsense
/// instances. pfSense has separate boolean fields for each push option; OPNsense
/// combines them into a single comma-separated list.
///
/// # Arguments
///
/// * `flags` - The accumulating list of enabled flags
/// * `flag` - The flag name to add (e.g., "block-outside-dns", "register-dns")
/// * `enabled` - Whether this flag is enabled
fn append_push_flag(flags: &mut Vec<&'static str>, flag: &'static str, enabled: bool) {
    if enabled {
        flags.push(flag);
    }
}
