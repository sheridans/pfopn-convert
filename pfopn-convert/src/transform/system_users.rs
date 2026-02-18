use xml_diff_core::XmlNode;

/// Convert user accounts from pfSense to OPNsense format.
///
/// Key differences:
/// - pfSense default admin user is named "admin"
/// - OPNsense default admin user is named "root"
/// - pfSense stores passwords as bcrypt-hash
/// - OPNsense stores passwords as plain "password" (still hashed, just different tag)
///
/// This function:
/// 1. Maps the source "admin" user to target "root" user with password conversion
/// 2. Copies all other GUI users (users with page-* privileges)
/// 3. Removes the old "admin" user to avoid duplicates
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, _destination_baseline: &XmlNode) {
    map_login_user(out, source, "admin", "root", "password");
    preserve_gui_users(out, source, "password");
    remove_user_by_name(out, "admin");
}

/// Convert user accounts from OPNsense to pfSense format.
///
/// Key differences:
/// - OPNsense default admin user is named "root"
/// - pfSense default admin user is named "admin"
/// - OPNsense stores passwords as "password"
/// - pfSense stores passwords as "bcrypt-hash"
///
/// This function:
/// 1. Maps the source "root" user to target "admin" user with password conversion
/// 2. Copies all other GUI users (users with page-* privileges)
/// 3. Removes the old "root" user to avoid duplicates
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, _destination_baseline: &XmlNode) {
    map_login_user(out, source, "root", "admin", "bcrypt-hash");
    preserve_gui_users(out, source, "bcrypt-hash");
    remove_user_by_name(out, "root");
}

/// Map the default admin user from source platform to target platform.
///
/// Example: When converting pfSense → OPNsense, this maps "admin" → "root".
///
/// The function:
/// 1. Finds the source admin user by name (e.g., "admin" for pfSense)
/// 2. If not found by name, falls back to finding the user with UID 0
/// 3. Extracts the user's password/hash
/// 4. Updates existing admin candidates in the target (by name or UID 0)
/// 5. If no admin exists in target, creates a new user with the target name
fn map_login_user(
    out: &mut XmlNode,
    source: &XmlNode,
    source_name: &str,
    target_name: &str,
    target_credential_tag: &str,
) {
    // Find the source admin user (e.g., "admin" in pfSense, "root" in OPNsense)
    // Fall back to UID 0 if the expected name isn't found (handles renamed admins)
    let Some(source_user) = find_user(source, source_name)
        .or_else(|| find_user_by_uid(source, "0"))
        .cloned()
    else {
        return;
    };

    let source_credential = user_credential(&source_user);
    let Some(system_out) = out.children.iter_mut().find(|n| n.tag == "system") else {
        return;
    };

    // Try to update existing admin users in the target (by name or UID 0)
    if update_existing_login_candidates(
        system_out,
        target_name,
        target_credential_tag,
        source_credential.as_deref(),
    ) {
        return; // Successfully updated existing user
    }

    // No existing admin found — create a new user with the target name
    let mut new_user = source_user;
    set_user_name(&mut new_user, target_name);
    set_user_credential(
        &mut new_user,
        target_credential_tag,
        source_credential.as_deref(),
    );
    system_out.children.push(new_user);
}

/// Update credentials for existing admin user candidates in the target.
///
/// Looks for users that match either the target name (e.g., "root") or have UID 0,
/// and updates their credentials to match the source admin user.
///
/// Returns true if at least one user was updated, false if none were found.
fn update_existing_login_candidates(
    system: &mut XmlNode,
    target_name: &str,
    target_credential_tag: &str,
    source_credential: Option<&str>,
) -> bool {
    let mut updated = false;
    for user in system.children.iter_mut().filter(|n| n.tag == "user") {
        // Check if this user matches by name (case-insensitive)
        let name_match = user
            .get_text(&["name"])
            .map(|v| v.trim().eq_ignore_ascii_case(target_name))
            .unwrap_or(false);

        // Check if this user has UID 0 (root user)
        let uid0 = user
            .get_text(&["uid"])
            .map(|v| v.trim() == "0")
            .unwrap_or(false);

        if name_match || uid0 {
            set_user_credential(user, target_credential_tag, source_credential);
            updated = true;
        }
    }
    updated
}

/// Find a user by username (case-insensitive) in the config root.
fn find_user<'a>(root: &'a XmlNode, wanted_name: &str) -> Option<&'a XmlNode> {
    let system = root.get_child("system")?;
    system.children.iter().find(|n| {
        n.tag == "user"
            && n.get_text(&["name"])
                .map(|name| name.trim().eq_ignore_ascii_case(wanted_name))
                .unwrap_or(false)
    })
}

/// Find a user by UID in the config root.
fn find_user_by_uid<'a>(root: &'a XmlNode, wanted_uid: &str) -> Option<&'a XmlNode> {
    let system = root.get_child("system")?;
    system.children.iter().find(|n| {
        n.tag == "user"
            && n.get_text(&["uid"])
                .map(|uid| uid.trim() == wanted_uid)
                .unwrap_or(false)
    })
}

/// Set or update the <name> field of a user node.
fn set_user_name(user: &mut XmlNode, name: &str) {
    if let Some(n) = user.children.iter_mut().find(|c| c.tag == "name") {
        n.text = Some(name.to_string());
        return;
    }
    let mut n = XmlNode::new("name");
    n.text = Some(name.to_string());
    user.children.push(n);
}

/// Extract a user's password/hash from any supported credential field.
///
/// Checks in priority order:
/// 1. <password> (OPNsense format, also used for legacy hashes)
/// 2. <bcrypt-hash> (pfSense format)
/// 3. <sha512-hash> (legacy format from older versions)
///
/// Returns the first non-empty credential found.
fn user_credential(user: &XmlNode) -> Option<String> {
    user.get_child("password")
        .and_then(|n| n.text.as_ref())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            user.get_child("bcrypt-hash")
                .and_then(|n| n.text.as_ref())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            user.get_child("sha512-hash")
                .and_then(|n| n.text.as_ref())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

/// Set or update a user's credential field with the preferred tag name.
///
/// The credential tag differs between platforms:
/// - pfSense uses `<bcrypt-hash>`
/// - OPNsense uses `<password>` (despite the name, this still stores a hash)
///
/// This function:
/// 1. If the preferred tag already exists, update its value
/// 2. If a different credential tag exists, rename it to the preferred tag
/// 3. Otherwise, create a new credential element with the preferred tag
fn set_user_credential(user: &mut XmlNode, preferred_tag: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };

    // If preferred tag already exists, just update its value
    if let Some(node) = user.children.iter_mut().find(|c| c.tag == preferred_tag) {
        node.text = Some(value.to_string());
        return;
    }

    // If any credential tag exists, rename it to the preferred tag
    if let Some(node) = user
        .children
        .iter_mut()
        .find(|c| c.tag == "password" || c.tag == "bcrypt-hash" || c.tag == "sha512-hash")
    {
        node.tag = preferred_tag.to_string();
        node.text = Some(value.to_string());
        return;
    }

    // No credential field exists — create one
    let mut n = XmlNode::new(preferred_tag);
    n.text = Some(value.to_string());
    user.children.push(n);
}

/// Remove a user by name from the system section.
///
/// Used to clean up the old default admin user after mapping (e.g., remove "admin"
/// after converting pfSense → OPNsense, since we've already mapped it to "root").
fn remove_user_by_name(root: &mut XmlNode, target_name: &str) {
    let Some(system) = root.children.iter_mut().find(|n| n.tag == "system") else {
        return;
    };
    system.children.retain(|n| {
        if n.tag != "user" {
            return true; // Keep non-user elements
        }
        // Keep users whose name doesn't match (case-insensitive)
        !n.get_text(&["name"])
            .map(|name| name.trim().eq_ignore_ascii_case(target_name))
            .unwrap_or(false)
    });
}

/// Internal representation of a GUI user during transfer.
struct GuiUser {
    name: String,        // Username (e.g., "alice")
    uid: Option<String>, // User ID for matching (if present)
    node: XmlNode,       // The sanitized user XML node
}

/// Copy additional GUI users from source to output (beyond the default admin user).
///
/// GUI users are users with web interface access (page-* privileges). This function:
/// 1. Collects all non-root GUI users from the source config
/// 2. Matches them to existing users in the output by UID or username
/// 3. Updates or creates users as needed
/// 4. Converts credential tags to match the target platform
fn preserve_gui_users(out: &mut XmlNode, source: &XmlNode, target_credential_tag: &str) {
    let gui_users = collect_gui_users(source);
    if gui_users.is_empty() {
        return;
    }
    let Some(system_out) = out.children.iter_mut().find(|n| n.tag == "system") else {
        return;
    };

    for gui_user in gui_users {
        apply_gui_user(system_out, &gui_user, target_credential_tag);
    }
}

/// Collect all GUI users from the source config (excluding UID 0/root/admin).
///
/// A GUI user is one that:
/// - Has UID != 0 (not the root admin)
/// - Is enabled (no <disabled>1</disabled>)
/// - Has GUI privileges (page-* privileges or is in the admins group)
///
/// Returns a sanitized version of each user with only fields safe to transfer.
fn collect_gui_users(root: &XmlNode) -> Vec<GuiUser> {
    let Some(system) = root.get_child("system") else {
        return Vec::new();
    };
    let mut out = Vec::new();

    for user in system.children.iter().filter(|n| n.tag == "user") {
        let uid = user.get_text(&["uid"]).map(|v| v.trim().to_string());

        // Skip UID 0 (root/admin) — that's handled separately
        if uid.as_deref() == Some("0") {
            continue;
        }

        // Skip disabled users
        if !is_enabled(user) {
            continue;
        }

        // Skip users without GUI access
        if !has_gui_privileges(user) {
            continue;
        }

        // Sanitize the user (remove fields that shouldn't transfer)
        let sanitized = sanitize_gui_user(user);
        let name = sanitized
            .get_text(&["name"])
            .map(|v| v.trim().to_string())
            .unwrap_or_default();

        // Skip users without a name or UID (can't match them)
        if name.is_empty() && uid.is_none() {
            continue;
        }

        out.push(GuiUser {
            name,
            uid,
            node: sanitized,
        });
    }
    out
}

/// Apply a GUI user to the output system, either updating an existing user or creating a new one.
///
/// Matching strategy:
/// 1. Try to match by UID (most reliable, since UIDs should be stable)
/// 2. Fall back to matching by username
/// 3. If no match, create a new user
fn apply_gui_user(system_out: &mut XmlNode, gui_user: &GuiUser, target_credential_tag: &str) {
    // Try matching by UID first (most reliable)
    if let Some(uid) = gui_user.uid.as_deref() {
        if uid != "0" {
            if let Some(dest_user) = find_user_by_uid_mut(system_out, uid) {
                // Found a UID match. If the name differs, warn about collision.
                if !names_equal(dest_user, &gui_user.name) {
                    eprintln!(
                        "warning: UID collision for GUI user {} (uid {}); falling back to name match",
                        gui_user.name, uid
                    );
                }
                update_gui_user(dest_user, gui_user, target_credential_tag);
                return;
            }
        }
    }

    // Try matching by name
    if let Some(dest_user) = find_user_by_name_mut(system_out, &gui_user.name) {
        update_gui_user(dest_user, gui_user, target_credential_tag);
        return;
    }

    // No match — create a new user
    let mut new_user = gui_user.node.clone();
    set_user_credential(
        &mut new_user,
        target_credential_tag,
        user_credential(&gui_user.node).as_deref(),
    );
    system_out.children.push(new_user);
}

/// Update an existing GUI user in the target with data from the source.
///
/// Updates:
/// - All privileges (<priv> elements)
/// - Description, scope, groupname, SSH keys
/// - Password/credential with platform-specific tag
fn update_gui_user(dest: &mut XmlNode, gui_user: &GuiUser, target_credential_tag: &str) {
    // Replace all privileges
    dest.children.retain(|child| child.tag != "priv");
    for priv_node in gui_user.node.get_children("priv") {
        dest.children.push(priv_node.clone());
    }

    // Copy other user fields
    copy_field(dest, &gui_user.node, "disabled");
    copy_field(dest, &gui_user.node, "descr");
    copy_field(dest, &gui_user.node, "scope");
    copy_field(dest, &gui_user.node, "groupname");
    copy_field(dest, &gui_user.node, "authorizedkeys");

    // Update credential with target platform's tag
    set_user_credential(
        dest,
        target_credential_tag,
        user_credential(&gui_user.node).as_deref(),
    );
}

/// Copy a single field from source to dest, creating or updating as needed.
fn copy_field(dest: &mut XmlNode, source: &XmlNode, tag: &str) {
    if let Some(value) = source
        .get_text(&[tag])
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        if let Some(node) = dest.children.iter_mut().find(|child| child.tag == tag) {
            node.text = Some(value.to_string());
            return;
        }
        let mut node = XmlNode::new(tag);
        node.text = Some(value.to_string());
        dest.children.push(node);
    }
}

/// Check if a user is enabled (not disabled).
///
/// Users are enabled by default unless they have <disabled>1</disabled>.
fn is_enabled(user: &XmlNode) -> bool {
    user.get_text(&["disabled"])
        .map(|v| !matches!(v.trim(), "1"))
        .unwrap_or(true) // Default to enabled if no disabled field
}

/// Check if a user has GUI/web interface privileges.
///
/// Returns true if:
/// - User is in the "admins" group, OR
/// - User has any "page-*" privilege (e.g., "page-all", "page-system-usermanager")
fn has_gui_privileges(user: &XmlNode) -> bool {
    if user_in_admin_group(user) {
        return true;
    }
    user.get_children("priv")
        .iter()
        .any(|p| p.text.as_deref().is_some_and(is_gui_priv))
}

/// Check if user is in the "admins" group.
fn user_in_admin_group(user: &XmlNode) -> bool {
    user.get_text(&["groupname"])
        .map(|g| g.trim().eq_ignore_ascii_case("admins"))
        .unwrap_or(false)
}

/// Check if a privilege string grants GUI/web access.
///
/// GUI privileges start with "page-" (e.g., "page-all", "page-system-usermanager").
fn is_gui_priv(privilege: &str) -> bool {
    let normalized = privilege.trim();
    normalized.eq_ignore_ascii_case("page-all") || normalized.starts_with("page-")
}

/// Create a sanitized copy of a user node with only allowed fields.
///
/// This prevents platform-specific or sensitive fields from leaking across
/// during conversion. Only copies: name, uid, credentials, privileges, description,
/// SSH keys, and group membership.
fn sanitize_gui_user(user: &XmlNode) -> XmlNode {
    let allowed = [
        "name",
        "uid",
        "disabled",
        "descr",
        "scope",
        "groupname",
        "priv",
        "password",
        "bcrypt-hash",
        "sha512-hash",
        "authorizedkeys",
    ];
    let mut sanitized = XmlNode::new("user");
    sanitized.attributes = user.attributes.clone();
    for child in &user.children {
        if allowed.contains(&child.tag.as_str()) {
            sanitized.children.push(child.clone());
        }
    }
    sanitized
}

/// Find a mutable user reference by UID in the system section.
fn find_user_by_uid_mut<'a>(system: &'a mut XmlNode, uid: &str) -> Option<&'a mut XmlNode> {
    system.children.iter_mut().find(|child| {
        child.tag == "user"
            && child
                .get_text(&["uid"])
                .map(|v| v.trim() == uid)
                .unwrap_or(false)
    })
}

/// Find a mutable user reference by name in the system section.
fn find_user_by_name_mut<'a>(system: &'a mut XmlNode, name: &str) -> Option<&'a mut XmlNode> {
    system.children.iter_mut().find(|child| {
        child.tag == "user"
            && child
                .get_text(&["name"])
                .map(|v| v.trim() == name.trim())
                .unwrap_or(false)
    })
}

/// Check if a user node's name matches a given string.
fn names_equal(user: &XmlNode, name: &str) -> bool {
    user.get_text(&["name"])
        .map(|v| v.trim() == name.trim())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{to_opnsense, to_pfsense};
    use xml_diff_core::parse;

    #[test]
    fn maps_admin_credentials_to_root() {
        let source = parse(
            br#"<pfsense><system><user><name>admin</name><bcrypt-hash>HASHA</bcrypt-hash></user></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><user><name>root</name><password>OLD</password></user></system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        let root_user = out
            .get_child("system")
            .and_then(|s| {
                s.children
                    .iter()
                    .find(|u| u.tag == "user" && u.get_text(&["name"]) == Some("root"))
            })
            .expect("root user");
        assert_eq!(root_user.get_text(&["password"]), Some("HASHA"));
        assert!(out
            .get_child("system")
            .expect("system")
            .children
            .iter()
            .all(|u| u.tag != "user" || u.get_text(&["name"]) != Some("admin")));
    }

    #[test]
    fn maps_root_credentials_to_admin() {
        let source = parse(
            br#"<opnsense><system><user><name>root</name><password>HASHB</password></user></system></opnsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<pfsense><system><user><name>admin</name><bcrypt-hash>OLD</bcrypt-hash></user></system></pfsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_pfsense(&mut out, &source, &baseline);
        let admin_user = out
            .get_child("system")
            .and_then(|s| {
                s.children
                    .iter()
                    .find(|u| u.tag == "user" && u.get_text(&["name"]) == Some("admin"))
            })
            .expect("admin user");
        assert_eq!(admin_user.get_text(&["bcrypt-hash"]), Some("HASHB"));
        assert!(out
            .get_child("system")
            .expect("system")
            .children
            .iter()
            .all(|u| u.tag != "user" || u.get_text(&["name"]) != Some("root")));
    }

    #[test]
    fn falls_back_to_uid_zero_when_default_name_missing() {
        let source = parse(
            br#"<pfsense><system><user><uid>0</uid><name>opsadmin</name><bcrypt-hash>HASH0</bcrypt-hash></user></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><user><name>root</name><password>OLD</password></user></system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        let root_user = out
            .get_child("system")
            .and_then(|s| {
                s.children
                    .iter()
                    .find(|u| u.tag == "user" && u.get_text(&["name"]) == Some("root"))
            })
            .expect("root user");
        assert_eq!(root_user.get_text(&["password"]), Some("HASH0"));
    }

    #[test]
    fn updates_uid0_even_if_root_name_differs() {
        let source = parse(
            br#"<pfsense><system><user><name>admin</name><bcrypt-hash>NEWROOT</bcrypt-hash></user></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><user><uid>0</uid><name>Root</name><password>OLD</password></user></system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        let user = out
            .get_child("system")
            .and_then(|s| s.children.iter().find(|u| u.tag == "user"))
            .expect("user");
        assert_eq!(user.get_text(&["password"]), Some("NEWROOT"));
    }

    #[test]
    fn maps_sha512_hash_when_password_missing() {
        let source = parse(
            br#"<pfsense><system><user><name>admin</name><sha512-hash>SHA512V</sha512-hash></user></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><user><uid>0</uid><name>root</name><password>OLD</password></user></system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        let root_user = out
            .get_child("system")
            .and_then(|s| {
                s.children
                    .iter()
                    .find(|u| u.tag == "user" && u.get_text(&["name"]) == Some("root"))
            })
            .expect("root user");
        assert_eq!(root_user.get_text(&["password"]), Some("SHA512V"));
    }

    #[test]
    fn preserves_gui_user_credentials() {
        let source = parse(
            br#"<pfsense><system><user><name>webuser</name><uid>1</uid><priv>page-all</priv><password>GUI_PASS</password></user></system></pfsense>"#,
        )
        .expect("source parse");
        let mut out =
            parse(br#"<opnsense><system><user><name>root</name><password>OLD</password></user></system></opnsense>"#)
                .expect("out parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        let system = out.get_child("system").expect("system");
        let gui_user = system
            .children
            .iter()
            .find(|u| u.tag == "user" && u.get_text(&["name"]) == Some("webuser"))
            .expect("webuser");
        assert_eq!(gui_user.get_text(&["password"]), Some("GUI_PASS"));
        assert!(gui_user
            .children
            .iter()
            .any(|child| child.tag == "priv" && child.text.as_deref() == Some("page-all")));
    }

    #[test]
    fn skips_disabled_gui_user() {
        let source = parse(
            br#"<pfsense><system><user><name>webuser</name><uid>2</uid><priv>page-all</priv><disabled>1</disabled><password>GUI_PASS</password></user></system></pfsense>"#,
        )
        .expect("source parse");
        let mut out =
            parse(br#"<opnsense><system><user><name>root</name><password>OLD</password></user></system></opnsense>"#)
                .expect("out parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        let system = out.get_child("system").expect("system");
        assert!(system
            .children
            .iter()
            .all(|u| u.get_text(&["name"]) != Some("webuser")));
    }

    #[test]
    fn handles_uid_collision_by_name() {
        let source = parse(
            br#"<pfsense><system><user><name>webuser</name><uid>5</uid><priv>page-all</priv><password>GUI_PASS</password></user></system></pfsense>"#,
        )
        .expect("source parse");
        let mut out = parse(
            br#"<opnsense><system><user><name>webuser</name><uid>6</uid><password>OLD</password></user><user><name>root</name><password>OLD2</password></user></system></opnsense>"#,
        )
        .expect("out parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        let system = out.get_child("system").expect("system");
        let gui_user = system
            .children
            .iter()
            .find(|u| u.tag == "user" && u.get_text(&["name"]) == Some("webuser"))
            .expect("webuser");
        assert_eq!(gui_user.get_text(&["password"]), Some("GUI_PASS"));
        assert_eq!(
            system
                .children
                .iter()
                .filter(|u| u.tag == "user" && u.get_text(&["name"]) == Some("webuser"))
                .count(),
            1
        );
    }
}
