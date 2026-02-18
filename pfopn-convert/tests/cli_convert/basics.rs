use super::*;

#[test]
fn convert_auto_to_opnsense_with_target_file() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output_path = dir.path().join("converted.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><subnet>24</subnet></lan></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan><subnet>24</subnet></lan></interfaces></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output_path))
        .arg("--from")
        .arg("auto")
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let converted = fs::read_to_string(&output_path).expect("converted file");
    assert!(converted.contains("<opnsense>"));
}

#[test]
fn convert_rejects_to_auto() {
    let dir = tempdir().expect("tempdir");
    let output_path = dir.path().join("converted.xml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg("--output")
        .arg(path_as_str(&output_path))
        .arg("--to")
        .arg("auto")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--to cannot be auto"));
}

#[test]
fn convert_requires_target_file_unless_minimal_template() {
    let dir = tempdir().expect("tempdir");
    let output_path = dir.path().join("converted.xml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg("--output")
        .arg(path_as_str(&output_path))
        .arg("--from")
        .arg("auto")
        .arg("--to")
        .arg("opnsense")
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing --target-file"));
}

#[test]
fn convert_allows_minimal_template_with_explicit_flag() {
    let dir = tempdir().expect("tempdir");
    let output_path = dir.path().join("converted.xml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg("--output")
        .arg(path_as_str(&output_path))
        .arg("--from")
        .arg("auto")
        .arg("--to")
        .arg("opnsense")
        .arg("--minimal-template")
        .assert()
        .failure()
        .stderr(predicate::str::contains("interface preflight failed"));
}

#[test]
fn convert_rejects_output_overwriting_input() {
    let input = fixture("fixtures/pfsense-base.xml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(&input)
        .arg("--output")
        .arg(&input)
        .arg("--from")
        .arg("auto")
        .arg("--to")
        .arg("opnsense")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "refusing to overwrite source file",
        ));
}
