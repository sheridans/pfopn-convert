use serde::Serialize;
use xml_diff_core::XmlNode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ConversionSummary {
    pub interfaces: usize,
    pub bridges: usize,
    pub aliases: usize,
    pub rules: usize,
    pub routes: usize,
    pub vpns: usize,
}

pub fn summarize(root: &XmlNode) -> ConversionSummary {
    ConversionSummary {
        interfaces: count_interfaces(root),
        bridges: count_bridges(root),
        aliases: count_aliases(root),
        rules: count_rules(root),
        routes: count_routes(root),
        vpns: count_vpns(root),
    }
}

pub fn render(summary: ConversionSummary) -> String {
    format!(
        "convert_summary interfaces={} bridges={} aliases={} rules={} routes={} vpns={}",
        summary.interfaces,
        summary.bridges,
        summary.aliases,
        summary.rules,
        summary.routes,
        summary.vpns
    )
}

fn count_interfaces(root: &XmlNode) -> usize {
    root.get_child("interfaces")
        .map(|n| n.children.len())
        .unwrap_or(0)
}

fn count_bridges(root: &XmlNode) -> usize {
    root.get_child("bridges")
        .map(|n| n.children.iter().filter(|c| c.tag == "bridged").count())
        .unwrap_or(0)
}

fn count_aliases(root: &XmlNode) -> usize {
    let top = root
        .get_child("aliases")
        .map(|n| n.children.iter().filter(|c| c.tag == "alias").count())
        .unwrap_or(0);
    let nested = root
        .get_child("OPNsense")
        .and_then(|o| o.get_child("Firewall"))
        .and_then(|f| f.get_child("Alias"))
        .and_then(|a| a.get_child("aliases"))
        .map(|n| n.children.iter().filter(|c| c.tag == "alias").count())
        .unwrap_or(0);
    top.max(nested)
}

fn count_rules(root: &XmlNode) -> usize {
    root.get_child("filter")
        .map(|n| n.children.iter().filter(|c| c.tag == "rule").count())
        .unwrap_or(0)
}

fn count_routes(root: &XmlNode) -> usize {
    root.get_child("staticroutes")
        .map(|n| n.children.len())
        .unwrap_or(0)
}

fn count_vpns(root: &XmlNode) -> usize {
    let openvpn = root
        .get_child("openvpn")
        .map(|o| {
            o.children
                .iter()
                .filter(|c| c.tag == "openvpn-server" || c.tag == "openvpn-client")
                .count()
        })
        .unwrap_or(0);
    let ipsec = usize::from(root.get_child("ipsec").is_some())
        + usize::from(
            root.get_child("OPNsense")
                .and_then(|o| o.get_child("IPsec"))
                .is_some(),
        );
    let wireguard = usize::from(root.get_child("wireguard").is_some())
        + usize::from(
            root.get_child("OPNsense")
                .and_then(|o| o.get_child("wireguard"))
                .is_some(),
        );
    let tailscale = usize::from(root.get_child("tailscale").is_some())
        + usize::from(root.get_child("tailscaleauth").is_some())
        + usize::from(
            root.get_child("installedpackages")
                .and_then(|i| i.get_child("tailscale"))
                .is_some(),
        )
        + usize::from(
            root.get_child("OPNsense")
                .and_then(|o| o.get_child("tailscale"))
                .is_some(),
        );
    openvpn + ipsec + wireguard + tailscale
}
