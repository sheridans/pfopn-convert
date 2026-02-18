use xml_diff_core::XmlNode;

use super::common::{is_truthy, push_text_child, text_or};

/// Map OPNsense OpenVPN instances to pfSense servers and clients.
///
/// Converts OPNsense's unified `<Instance>` structure into pfSense's separate
/// `<openvpn-server>` and `<openvpn-client>` elements.
///
/// ## Mapping Strategy
///
/// - Instances are filtered by `<role>` field:
///   - `role="server"` → `<openvpn-server>`
///   - `role="client"` → `<openvpn-client>` (currently only servers are mapped)
/// - Preserves instance UUIDs as `<opnsense_instance_uuid>` for round-trip conversion
/// - Converts field names and structures between formats:
///   - `<enabled>` (OPNsense) → `<disable>` (pfSense, presence indicates disabled)
///   - `<dev_type>` → `<dev_mode>`
///   - DNS/NTP servers: comma-separated lists → numbered fields (dns_server1, dns_server2, etc.)
///   - Push flags: comma-separated list → separate boolean fields
///
/// ## Field Mapping Details
///
/// **Basic Settings:**
/// - `vpnid` — OpenVPN instance number (maps to ovpnsN interface)
/// - `protocol` — Connection protocol (UDP/TCP), case differs between platforms
/// - `port` → `local_port` — Listening port
/// - `server` → `tunnel_network` — VPN tunnel network (e.g., 10.8.0.0/24)
/// - `push_route` → `local_network` — Routes pushed to clients
///
/// **Authentication:**
/// - `ca` → `caref` — Certificate Authority reference
/// - `cert` → `certref` — Server certificate reference
/// - `cert_depth` — Maximum certificate chain depth
///
/// **DNS and Routing:**
/// - `dns_servers` (comma-separated) → `dns_server1`, `dns_server2`, etc. (up to 4)
/// - `ntp_servers` (comma-separated) → `ntp_server1`, `ntp_server2` (up to 2)
/// - `dns_domain` — DNS domain pushed to clients
///
/// **Advanced Options:**
/// - `various_push_flags` (comma-separated) → separate fields:
///   - "block-outside-dns" → `push_blockoutsidedns`
///   - "register-dns" → `push_register_dns`
///   - "explicit-exit-notify" → `exit_notify`
///
/// # Arguments
///
/// * `source` - The OPNsense configuration containing instances
///
/// # Returns
///
/// An `<openvpn>` node containing `<openvpn-server>` and/or `<openvpn-client>` children
pub(super) fn map_opnsense_instances_to_pfsense(source: &XmlNode) -> XmlNode {
    let mut openvpn = XmlNode::new("openvpn");
    let Some(instances) = source
        .get_child("OPNsense")
        .and_then(|n| n.get_child("OpenVPN"))
        .and_then(|n| n.get_child("Instances"))
    else {
        return openvpn;
    };

    // Convert each OPNsense instance to a pfSense server or client
    for instance in instances.get_children("Instance") {
        let role = text_or(instance, &["role"], "server").to_ascii_lowercase();
        // Currently only mapping servers; clients could be added here
        if role != "server" {
            continue;
        }

        let mut server = XmlNode::new("openvpn-server");
        // Preserve the UUID for round-trip conversion
        if let Some(uuid) = instance.attributes.get("uuid").map(String::as_str) {
            push_text_child(&mut server, "opnsense_instance_uuid", uuid);
        }
        push_text_child(&mut server, "vpnid", text_or(instance, &["vpnid"], "1"));
        // OPNsense uses <enabled>1</enabled>, pfSense uses <disable/> (empty element = disabled)
        if !is_truthy(text_or(instance, &["enabled"], "1")) {
            server.children.push(XmlNode::new("disable"));
        }
        push_text_child(&mut server, "mode", "server_tls");
        push_text_child(
            &mut server,
            "protocol",
            text_or(instance, &["proto"], "udp").to_ascii_uppercase(),
        );
        push_text_child(
            &mut server,
            "dev_mode",
            text_or(instance, &["dev_type"], "tun").to_ascii_lowercase(),
        );
        push_text_child(&mut server, "interface", "wan");
        push_text_child(&mut server, "local_port", text_or(instance, &["port"], ""));
        push_text_child(
            &mut server,
            "description",
            text_or(instance, &["description"], ""),
        );
        push_text_child(&mut server, "caref", text_or(instance, &["ca"], ""));
        push_text_child(&mut server, "certref", text_or(instance, &["cert"], ""));
        push_text_child(
            &mut server,
            "cert_depth",
            text_or(instance, &["cert_depth"], "1"),
        );
        push_text_child(
            &mut server,
            "tunnel_network",
            text_or(instance, &["server"], ""),
        );
        push_text_child(
            &mut server,
            "local_network",
            text_or(instance, &["push_route"], ""),
        );
        push_text_child(
            &mut server,
            "topology",
            text_or(instance, &["topology"], "subnet"),
        );

        // DNS domain and servers: OPNsense uses comma-separated, pfSense uses numbered fields
        if let Some(domain) = instance
            .get_text(&["dns_domain"])
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            push_text_child(&mut server, "dns_domain", domain);
        }
        // Convert comma-separated DNS servers to dns_server1, dns_server2, etc. (max 4)
        let dns_servers = split_csv(&text_or(instance, &["dns_servers"], ""));
        for (idx, dns) in dns_servers.into_iter().enumerate().take(4) {
            let mut child = XmlNode::new(format!("dns_server{}", idx + 1));
            child.text = Some(dns);
            server.children.push(child);
        }

        // Convert comma-separated NTP servers to ntp_server1, ntp_server2 (max 2)
        let ntp_servers = split_csv(&text_or(instance, &["ntp_servers"], ""));
        for (idx, ntp) in ntp_servers.into_iter().enumerate().take(2) {
            let mut child = XmlNode::new(format!("ntp_server{}", idx + 1));
            child.text = Some(ntp);
            server.children.push(child);
        }

        // Custom options
        if let Some(custom) = instance
            .get_text(&["custom_options"])
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            push_text_child(&mut server, "custom_options", custom);
        }

        // Username handling
        if let Some(username) = instance
            .get_text(&["username"])
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            push_text_child(&mut server, "username", username);
        }
        if is_truthy(text_or(instance, &["username_as_common_name"], "0")) {
            push_text_child(&mut server, "username_as_common_name", "enabled");
        }
        if is_truthy(text_or(instance, &["strictusercn"], "0")) {
            push_text_child(&mut server, "strictusercn", "1");
        }

        // Push flags
        let push_flags = split_csv(&text_or(instance, &["various_push_flags"], ""));
        if flag_present(&push_flags, "block-outside-dns") {
            push_text_child(&mut server, "push_blockoutsidedns", "yes");
        }
        if flag_present(&push_flags, "register-dns")
            || is_truthy(text_or(instance, &["register_dns"], "0"))
        {
            push_text_child(&mut server, "push_register_dns", "yes");
        }
        if flag_present(&push_flags, "explicit-exit-notify") {
            push_text_child(&mut server, "exit_notify", "explicit");
        }

        // NetBIOS
        if is_truthy(text_or(instance, &["netbios_enable"], "0")) {
            push_text_child(&mut server, "netbios_enable", "yes");
        }
        if let Some(netbios_ntype) = instance
            .get_text(&["netbios_ntype"])
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            push_text_child(&mut server, "netbios_ntype", netbios_ntype);
        }
        if let Some(netbios_scope) = instance
            .get_text(&["netbios_scope"])
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            push_text_child(&mut server, "netbios_scope", netbios_scope);
        }

        openvpn.children.push(server);
    }

    openvpn
}

/// Split a comma-separated value string into a vector of trimmed, non-empty strings.
///
/// Used for parsing OPNsense's comma-separated lists like DNS servers, NTP servers,
/// and push flags.
///
/// # Example
///
/// ```ignore
/// assert_eq!(split_csv("8.8.8.8, 8.8.4.4, "), vec!["8.8.8.8", "8.8.4.4"]);
/// assert_eq!(split_csv(""), vec![]);
/// ```
fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Check if a specific flag is present in a list of push flags.
///
/// Case-insensitive comparison to handle variations in flag naming.
///
/// # Example
///
/// ```ignore
/// let flags = vec!["block-outside-dns".to_string(), "register-dns".to_string()];
/// assert!(flag_present(&flags, "Block-Outside-DNS"));
/// assert!(flag_present(&flags, "register-dns"));
/// assert!(!flag_present(&flags, "explicit-exit-notify"));
/// ```
fn flag_present(flags: &[String], key: &str) -> bool {
    flags.iter().any(|flag| flag.eq_ignore_ascii_case(key))
}
