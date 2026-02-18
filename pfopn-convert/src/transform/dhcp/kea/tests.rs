use xml_diff_core::parse;

use super::migrate_isc_to_kea_opnsense;

#[test]
fn migrates_isc_v4_and_v6_into_kea() {
    let source = parse(
        br#"<pfsense>
            <interfaces>
              <lan><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet><ipaddrv6>fd00:1::1</ipaddrv6><subnetv6>64</subnetv6></lan>
            </interfaces>
            <dhcpd>
              <lan>
                <range><from>192.168.1.100</from><to>192.168.1.200</to></range>
                <range><from>192.168.1.210</from><to>192.168.1.220</to></range>
                <gateway>192.168.1.1</gateway>
                <domain>example.com</domain>
                <domainsearchlist>example.com;lab.local</domainsearchlist>
                <dnsserver>192.168.1.1</dnsserver>
                <ntpserver>192.168.1.1</ntpserver>
                <staticmap><mac>aa:bb:cc:dd:ee:ff</mac><ipaddr>192.168.1.20</ipaddr><hostname>printer</hostname><cid>01:aa:bb</cid><descr>v4 reservation</descr></staticmap>
              </lan>
            </dhcpd>
            <dhcpdv6>
              <lan>
                <range><from>::100</from><to>::200</to></range>
                <domainsearchlist>v6.lab.local</domainsearchlist>
                <dnsserver>fd00:1::1</dnsserver>
                <staticmap><duid>00:01:00:01:29:4a:7c:3a:52:54:00:12:34:56</duid><ipaddrv6>::123</ipaddrv6><hostname>hostv6</hostname><descr>v6 reservation</descr><domainsearchlist>v6a.local;v6b.local</domainsearchlist></staticmap>
              </lan>
            </dhcpdv6>
        </pfsense>"#,
    )
    .expect("parse");
    let mut out = parse(
        br#"<opnsense><OPNsense><Kea><dhcp4><general><enabled>0</enabled></general><subnets/><reservations/></dhcp4><dhcp6><general><enabled>0</enabled></general><subnets/><reservations/></dhcp6></Kea></OPNsense></opnsense>"#,
    )
    .expect("parse");

    let stats = migrate_isc_to_kea_opnsense(&mut out, &source).expect("migrate");
    assert_eq!(stats.reservations_added_v4, 1);
    assert_eq!(stats.reservations_added_v6, 1);
    assert_eq!(stats.subnets_added_v4, 1);
    assert_eq!(stats.subnets_added_v6, 1);
    assert!(stats.options_applied_v4 >= 1);
    assert!(stats.options_applied_v6 >= 1);
    assert_eq!(
        out.get_text(&["OPNsense", "Kea", "dhcp4", "general", "enabled"]),
        Some("1")
    );
    assert_eq!(
        out.get_text(&["OPNsense", "Kea", "dhcp6", "general", "enabled"]),
        Some("1")
    );
    assert_eq!(
        out.get_text(&[
            "OPNsense",
            "Kea",
            "dhcp4",
            "reservations",
            "reservation",
            "ip_address"
        ]),
        Some("192.168.1.20")
    );
    assert_eq!(
        out.get_text(&[
            "OPNsense",
            "Kea",
            "dhcp4",
            "reservations",
            "reservation",
            "client_id"
        ]),
        Some("01:aa:bb")
    );
    assert_eq!(
        out.get_text(&[
            "OPNsense",
            "Kea",
            "dhcp4",
            "reservations",
            "reservation",
            "description"
        ]),
        Some("v4 reservation")
    );
    assert_eq!(
        out.get_text(&["OPNsense", "Kea", "dhcp4", "subnets", "subnet4", "pools"]),
        Some("192.168.1.100-192.168.1.200,192.168.1.210-192.168.1.220")
    );
    assert_eq!(
        out.get_text(&[
            "OPNsense",
            "Kea",
            "dhcp6",
            "reservations",
            "reservation",
            "duid"
        ]),
        Some("00:01:00:01:29:4a:7c:3a:52:54:00:12:34:56")
    );
    assert_eq!(
        out.get_text(&[
            "OPNsense",
            "Kea",
            "dhcp6",
            "reservations",
            "reservation",
            "description"
        ]),
        Some("v6 reservation")
    );
    assert_eq!(
        out.get_text(&[
            "OPNsense",
            "Kea",
            "dhcp6",
            "reservations",
            "reservation",
            "domain_search"
        ]),
        Some("v6a.local v6b.local")
    );
}

#[test]
fn fails_when_reservation_iface_missing_network() {
    let source = parse(
        br#"<pfsense>
            <interfaces><lan><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces>
            <dhcpd><opt9><staticmap><mac>aa:bb:cc:dd:ee:ff</mac><ipaddr>10.10.10.10</ipaddr></staticmap></opt9></dhcpd>
        </pfsense>"#,
    )
    .expect("parse");
    let mut out = parse(
        br#"<opnsense><OPNsense><Kea><dhcp4><general><enabled>0</enabled></general><subnets/><reservations/></dhcp4></Kea></OPNsense></opnsense>"#,
    )
    .expect("parse");

    let err = migrate_isc_to_kea_opnsense(&mut out, &source).expect_err("must fail");
    assert!(err
        .to_string()
        .contains("missing interfaces.opt9.ipaddr/subnet"));
}

#[test]
fn migrates_v6_from_dhcpd6_alias_section() {
    let source = parse(
        br#"<pfsense>
            <interfaces><lan><ipaddrv6>fd00:1::1</ipaddrv6><subnetv6>64</subnetv6></lan></interfaces>
            <dhcpd6>
              <lan>
                <enable>1</enable>
                <range><from>::100</from><to>::200</to></range>
                <staticmap><duid>00:01:00:01:29:4a:7c:3a:52:54:00:12:34:56</duid><ipaddrv6>::123</ipaddrv6></staticmap>
              </lan>
            </dhcpd6>
        </pfsense>"#,
    )
    .expect("parse");
    let mut out = parse(
        br#"<opnsense><OPNsense><Kea><dhcp6><general><enabled>0</enabled></general><subnets/><reservations/></dhcp6></Kea></OPNsense></opnsense>"#,
    )
        .expect("parse");

    let stats = migrate_isc_to_kea_opnsense(&mut out, &source).expect("migrate");
    assert_eq!(stats.subnets_added_v6, 1);
    assert_eq!(stats.reservations_added_v6, 1);
    assert_eq!(
        out.get_text(&["OPNsense", "Kea", "dhcp6", "general", "enabled"]),
        Some("1")
    );
}

#[test]
fn warns_when_dhcpv6_intent_missing_prefix() {
    let source = parse(
        br#"<pfsense>
            <dhcpdv6>
              <lan>
                <range><from>::100</from><to>::200</to></range>
              </lan>
            </dhcpdv6>
        </pfsense>"#,
    )
    .expect("parse");
    let mut out = parse(
        br#"<opnsense><OPNsense><Kea><dhcp6><general><enabled>0</enabled></general><subnets/><reservations/></dhcp6></Kea></OPNsense></opnsense>"#,
    )
    .expect("parse");

    let stats = migrate_isc_to_kea_opnsense(&mut out, &source).expect("migrate");
    assert!(stats.warnings.iter().any(|w| w.message.contains("lan")));
    assert_eq!(stats.subnets_added_v6, 0);
    assert_eq!(stats.reservations_added_v6, 0);
    assert_eq!(
        out.get_text(&["OPNsense", "Kea", "dhcp6", "general", "enabled"]),
        Some("0")
    );
}

#[test]
fn skips_v6_when_no_intent() {
    let source = parse(
        br#"<pfsense>
            <interfaces><lan><ipaddrv6>fe80::1</ipaddrv6><subnetv6>64</subnetv6></lan></interfaces>
        </pfsense>"#,
    )
    .expect("parse");
    let mut out = parse(
        br#"<opnsense><OPNsense><Kea><dhcp6><general><enabled>0</enabled></general><subnets/><reservations/></dhcp6></Kea></OPNsense></opnsense>"#,
    )
    .expect("parse");

    let stats = migrate_isc_to_kea_opnsense(&mut out, &source).expect("migrate");
    assert!(stats.warnings.is_empty());
    assert_eq!(stats.subnets_added_v6, 0);
}

#[test]
fn partially_migrates_v6_when_one_iface_ready() {
    let source = parse(
        br#"<pfsense>
            <interfaces>
              <lan><ipaddrv6>fd00:1::1</ipaddrv6><subnetv6>64</subnetv6></lan>
              <opt1></opt1>
            </interfaces>
            <dhcpdv6>
              <lan>
                <range><from>::100</from><to>::200</to></range>
              </lan>
              <opt1>
                <range><from>::300</from><to>::400</to></range>
              </opt1>
            </dhcpdv6>
        </pfsense>"#,
    )
    .expect("parse");
    let mut out = parse(
        br#"<opnsense><OPNsense><Kea><dhcp6><general><enabled>0</enabled></general><subnets/><reservations/></dhcp6></Kea></OPNsense></opnsense>"#,
    )
    .expect("parse");

    let stats = migrate_isc_to_kea_opnsense(&mut out, &source).expect("migrate");
    assert_eq!(stats.subnets_added_v6, 1);
    assert!(stats.warnings.iter().any(|w| w.message.contains("opt1")));
}

#[test]
fn does_not_migrate_from_disabled_isc_interface() {
    let source = parse(
        br#"<pfsense>
            <interfaces><lan><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces>
            <dhcpd><lan><enable>0</enable><range><from>192.168.1.100</from><to>192.168.1.200</to></range></lan></dhcpd>
        </pfsense>"#,
    )
    .expect("parse");
    let mut out = parse(
        br#"<opnsense><OPNsense><Kea><dhcp4><general><enabled>0</enabled></general><subnets/><reservations/></dhcp4></Kea></OPNsense></opnsense>"#,
    )
    .expect("parse");

    let stats = migrate_isc_to_kea_opnsense(&mut out, &source).expect("migrate");
    assert_eq!(stats.subnets_added_v4, 0);
    assert_eq!(stats.reservations_added_v4, 0);
    assert_eq!(
        out.get_text(&["OPNsense", "Kea", "dhcp4", "general", "enabled"]),
        Some("0")
    );
}

#[test]
fn reports_skipped_reservation_conflicts() {
    let source = parse(
        br#"<pfsense>
            <interfaces><lan><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces>
            <dhcpd>
              <lan>
                <enable>1</enable>
                <range><from>192.168.1.100</from><to>192.168.1.200</to></range>
                <staticmap><mac>aa:aa:aa:aa:aa:aa</mac><ipaddr>192.168.1.25</ipaddr></staticmap>
              </lan>
            </dhcpd>
        </pfsense>"#,
    )
    .expect("parse");
    let mut out = parse(
        br#"<opnsense><OPNsense><Kea><dhcp4><general><enabled>1</enabled><interfaces>lan</interfaces></general><subnets><subnet4 uuid="sub1"><subnet>192.168.1.0/24</subnet><option_data/></subnet4></subnets><reservations><reservation><hw_address>bb:bb:bb:bb:bb:bb</hw_address><ip_address>192.168.1.25</ip_address><subnet>sub1</subnet></reservation></reservations></dhcp4></Kea></OPNsense></opnsense>"#,
    )
    .expect("parse");

    let stats = migrate_isc_to_kea_opnsense(&mut out, &source).expect("migrate");
    assert_eq!(stats.reservations_added_v4, 0);
    assert_eq!(stats.reservations_skipped_conflict_v4, 1);
}
