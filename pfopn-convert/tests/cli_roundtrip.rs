use std::fs;

use assert_cmd::Command;
use tempfile::tempdir;

fn run_success(args: &[&str]) -> String {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"))
        .args(args)
        .output()
        .expect("command output");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn roundtrip_opnsense_to_pfsense_back_has_no_modified_or_structural_diff() {
    let dir = tempdir().expect("tempdir");
    let opn_src = dir.path().join("opn-src.xml");
    let pf_base = dir.path().join("pf-base.xml");
    let to_pf = dir.path().join("opn-to-pf.xml");
    let back_to_opn = dir.path().join("opn-back.xml");

    fs::write(
        &opn_src,
        r#"<opnsense>
<version>24.7</version>
<system/>
<interfaces><lan><if>igc1</if><subnet>24</subnet></lan></interfaces>
<filter><rule><interface>lan</interface><type>pass</type></rule></filter>
</opnsense>"#,
    )
    .expect("write opn src");
    fs::write(
        &pf_base,
        r#"<pfsense>
<version>2.7.2</version>
<system/>
<interfaces><lan><if>igc1</if><subnet>24</subnet></lan></interfaces>
<filter><rule><interface>lan</interface><type>pass</type></rule></filter>
</pfsense>"#,
    )
    .expect("write pf base");

    run_success(&[
        "convert",
        opn_src.to_str().expect("utf8 path"),
        "--from",
        "opnsense",
        "--to",
        "pfsense",
        "--target-file",
        pf_base.to_str().expect("utf8 path"),
        "--output",
        to_pf.to_str().expect("utf8 path"),
    ]);

    run_success(&[
        "convert",
        to_pf.to_str().expect("utf8 path"),
        "--from",
        "pfsense",
        "--to",
        "opnsense",
        "--target-file",
        opn_src.to_str().expect("utf8 path"),
        "--output",
        back_to_opn.to_str().expect("utf8 path"),
    ]);

    let summary = run_success(&[
        "diff",
        opn_src.to_str().expect("utf8 path"),
        back_to_opn.to_str().expect("utf8 path"),
        "--summary",
    ]);
    assert!(summary.contains("modified=0"), "{summary}");
    assert!(summary.contains("structural=0"), "{summary}");
}

#[test]
fn roundtrip_pfsense_to_opnsense_back_has_no_modified_or_structural_diff() {
    let dir = tempdir().expect("tempdir");
    let pf_src = dir.path().join("pf-src.xml");
    let opn_base = dir.path().join("opn-base.xml");
    let to_opn = dir.path().join("pf-to-opn.xml");
    let back_to_pf = dir.path().join("pf-back.xml");

    fs::write(
        &pf_src,
        r#"<pfsense>
<version>2.7.2</version>
<system/>
<interfaces><lan><if>igc1</if><subnet>24</subnet></lan></interfaces>
<filter><rule><interface>lan</interface><type>pass</type></rule></filter>
</pfsense>"#,
    )
    .expect("write pf src");
    fs::write(
        &opn_base,
        r#"<opnsense>
<version>24.7</version>
<system/>
<interfaces><lan><if>igc1</if><subnet>24</subnet></lan></interfaces>
<filter><rule><interface>lan</interface><type>pass</type></rule></filter>
</opnsense>"#,
    )
    .expect("write opn base");

    run_success(&[
        "convert",
        pf_src.to_str().expect("utf8 path"),
        "--from",
        "pfsense",
        "--to",
        "opnsense",
        "--target-file",
        opn_base.to_str().expect("utf8 path"),
        "--output",
        to_opn.to_str().expect("utf8 path"),
    ]);

    run_success(&[
        "convert",
        to_opn.to_str().expect("utf8 path"),
        "--from",
        "opnsense",
        "--to",
        "pfsense",
        "--target-file",
        pf_src.to_str().expect("utf8 path"),
        "--output",
        back_to_pf.to_str().expect("utf8 path"),
    ]);

    let summary = run_success(&[
        "diff",
        pf_src.to_str().expect("utf8 path"),
        back_to_pf.to_str().expect("utf8 path"),
        "--summary",
    ]);
    assert!(summary.contains("modified=0"), "{summary}");
    assert!(summary.contains("structural=0"), "{summary}");
}
