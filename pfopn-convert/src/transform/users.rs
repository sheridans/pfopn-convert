use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

/// Transfer all users from pfSense to OPNsense, mapping the default admin.
///
/// This is a simpler version of system_users.rs that just copies all users
/// wholesale, with special handling for the default admin user name change
/// (admin → root).
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, _destination_baseline: &XmlNode) {
    transfer_users(out, source, Some(("admin", "root")));
}

/// Transfer all users from OPNsense to pfSense, mapping the default admin.
///
/// This is a simpler version of system_users.rs that just copies all users
/// wholesale, with special handling for the default admin user name change
/// (root → admin).
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, _destination_baseline: &XmlNode) {
    transfer_users(out, source, Some(("root", "admin")));
}

/// Copy all users from source to output, optionally remapping the default admin name.
///
/// This is a lightweight alternative to system_users.rs. It:
/// - Copies all users from source that don't already exist in output
/// - Handles the admin name mapping (admin ↔ root)
/// - Skips users if a user with that name already exists in output
/// - Does NOT update credentials, privileges, or other user fields
///
/// Use this when you want to preserve all source users exactly as-is.
fn transfer_users(out: &mut XmlNode, source: &XmlNode, map_default: Option<(&str, &str)>) {
    let Some(source_system) = source.get_child("system") else {
        return;
    };

    // Collect all users from source that have a name
    let source_users: Vec<XmlNode> = source_system
        .children
        .iter()
        .filter(|c| c.tag == "user" && c.get_text(&["name"]).is_some())
        .cloned()
        .collect();

    if source_users.is_empty() {
        return;
    }

    let Some(out_system) = out.children.iter_mut().find(|c| c.tag == "system") else {
        return;
    };

    // Build a set of existing usernames in the output (for de-duplication)
    let mut existing: BTreeSet<String> = out_system
        .children
        .iter()
        .filter(|c| c.tag == "user")
        .filter_map(|u| u.get_text(&["name"]))
        .map(ToOwned::to_owned)
        .collect();

    for mut user in source_users {
        let Some(name) = user.get_text(&["name"]).map(ToOwned::to_owned) else {
            continue;
        };

        // Handle admin name mapping (e.g., "admin" → "root")
        if let Some((from_default, to_default)) = map_default {
            if name.eq_ignore_ascii_case(from_default) {
                // Only add if the target name doesn't already exist
                if !existing.iter().any(|n| n.eq_ignore_ascii_case(to_default)) {
                    set_user_name(&mut user, to_default);
                    out_system.children.push(user);
                    existing.insert(to_default.to_string());
                }
                continue;
            }
        }

        // Skip if a user with this name already exists
        if existing.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
            continue;
        }

        existing.insert(name);
        out_system.children.push(user);
    }
}

/// Set the <name> field of a user node.
fn set_user_name(user: &mut XmlNode, name: &str) {
    if let Some(n) = user.children.iter_mut().find(|c| c.tag == "name") {
        n.text = Some(name.to_string());
        return;
    }
    let mut n = XmlNode::new("name");
    n.text = Some(name.to_string());
    user.children.push(n);
}

#[cfg(test)]
mod tests {
    use super::{to_opnsense, to_pfsense};
    use xml_diff_core::parse;

    #[test]
    fn transfers_all_users_and_maps_admin_to_root() {
        let source = parse(
            br#"<pfsense><system><user><name>admin</name></user><user><name>alice</name></user></system></pfsense>"#,
        )
        .expect("parse");
        let mut out =
            parse(br#"<opnsense><system><user><name>root</name></user></system></opnsense>"#)
                .expect("parse");
        let baseline = out.clone();
        to_opnsense(&mut out, &source, &baseline);

        let users: Vec<&str> = out
            .get_child("system")
            .expect("system")
            .children
            .iter()
            .filter(|n| n.tag == "user")
            .filter_map(|u| u.get_text(&["name"]))
            .collect();
        assert!(users.contains(&"root"));
        assert!(users.contains(&"alice"));
        assert!(!users.contains(&"admin"));
    }

    #[test]
    fn transfers_all_users_and_maps_root_to_admin() {
        let source = parse(
            br#"<opnsense><system><user><name>root</name></user><user><name>bob</name></user></system></opnsense>"#,
        )
        .expect("parse");
        let mut out =
            parse(br#"<pfsense><system><user><name>admin</name></user></system></pfsense>"#)
                .expect("parse");
        let baseline = out.clone();
        to_pfsense(&mut out, &source, &baseline);

        let users: Vec<&str> = out
            .get_child("system")
            .expect("system")
            .children
            .iter()
            .filter(|n| n.tag == "user")
            .filter_map(|u| u.get_text(&["name"]))
            .collect();
        assert!(users.contains(&"admin"));
        assert!(users.contains(&"bob"));
        assert!(!users.contains(&"root"));
    }
}
