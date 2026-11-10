//! The tests for the alerts engine.
//!
//! The values here are synthetic: the `00:11:22:33:44:xx` MAC family and
//! `example-*` SSIDs, as the rest of the project uses. The frames come from
//! the `od3sa-fixtures` builders and the observations from the
//! `od3sa-store` aggregator, so no real capture is involved anywhere.

use od3sa_fixtures::{AKM_PSK, AKM_SAE, beacon, beacon_with_akm, deauth_frame, mac, probe_request};
use od3sa_store::{Aggregator, LinkLayer, Observation};

use crate::{Alert, AlertEngine, Rules, Severity};

/// The time the synthetic frames are seen at, in unix epoch milliseconds.
const NOW_MS: i64 = 1_700_000_000_000;

/// The name of the source that sees the synthetic frames.
const SOURCE: &str = "example-source";

/// A configuration with every rule off.
const NOTHING: &str = "enabled = true";

/// The rules of a configuration, parsed.
fn parsed(text: &str) -> Rules {
    Rules::parse(text).expect("the configuration should parse")
}

/// An engine with the given configuration.
fn engine_with(text: &str) -> AlertEngine {
    AlertEngine::new(parsed(text))
}

/// The rules of an engine, for the rule that raised an alert.
fn rule_of(alert: &Alert) -> &str {
    &alert.rule
}

/// The alerts of one rule.
fn of_rule<'a>(alerts: &'a [Alert], rule: &str) -> Vec<&'a Alert> {
    alerts
        .iter()
        .filter(|alert| rule_of(alert) == rule)
        .collect()
}

/// The aggregator, with a table big enough for the tests.
fn new_aggregator() -> Aggregator {
    Aggregator::new(1024)
}

/// Feed one frame through the aggregator and return what it made of it.
fn observe(aggregator: &mut Aggregator, frame: &[u8], ts_ms: i64) -> Observation {
    aggregator
        .observe(frame, LinkLayer::Radiotap, ts_ms, SOURCE)
        .expect("the frame should be observed")
}

/// The beacon of one access point.
fn beacon_of(bssid: [u8; 6], ssid: &str, rssi: i8) -> Vec<u8> {
    beacon(bssid, ssid, 2412, rssi, true)
}

#[test]
fn new_device_raises_once_for_a_device_and_not_again() {
    let mut engine = engine_with("new_device = { enabled = true, severity = \"info\" }");
    let mut aggregator = new_aggregator();

    let frame = probe_request(mac(11), "example-ssid", -48, 2412);

    let first = engine.observe(&observe(&mut aggregator, &frame, NOW_MS), NOW_MS);
    let alerts = of_rule(&first, "new_device");
    assert_eq!(alerts.len(), 1, "the first sighting raises once");
    assert_eq!(alerts[0].severity, Severity::Info);
    assert_eq!(alerts[0].mac, Some(mac(11)));

    let second = engine.observe(
        &observe(&mut aggregator, &frame, NOW_MS + 1000),
        NOW_MS + 1000,
    );
    assert!(
        of_rule(&second, "new_device").is_empty(),
        "the same device seen again raises nothing"
    );

    // A different device does raise.
    let other = probe_request(mac(12), "example-ssid", -48, 2412);
    let third = engine.observe(
        &observe(&mut aggregator, &other, NOW_MS + 2000),
        NOW_MS + 2000,
    );
    assert_eq!(of_rule(&third, "new_device").len(), 1);
}

#[test]
fn watchlist_raises_for_a_listed_mac_a_listed_oui_and_a_listed_ssid() {
    // A listed MAC.
    let mut engine = engine_with(
        "watchlist = { enabled = true, severity = \"warning\", macs = [\"00:11:22:33:44:0b\"] }",
    );
    let mut aggregator = new_aggregator();

    let listed = probe_request(mac(0x0b), "example-ssid", -48, 2412);
    let alerts = engine.observe(&observe(&mut aggregator, &listed, NOW_MS), NOW_MS);
    let watchlist = of_rule(&alerts, "watchlist");
    assert_eq!(watchlist.len(), 1, "the listed MAC raises");
    assert_eq!(watchlist[0].severity, Severity::Warning);
    assert_eq!(watchlist[0].mac, Some(mac(0x0b)));

    // A MAC that is not on the list.
    let other = probe_request(mac(0x0c), "example-ssid", -48, 2412);
    let alerts = engine.observe(
        &observe(&mut aggregator, &other, NOW_MS + 1000),
        NOW_MS + 1000,
    );
    assert!(
        of_rule(&alerts, "watchlist").is_empty(),
        "a MAC that is not on the list raises nothing"
    );

    // A listed OUI. Every fixture address shares the OUI, so this is a
    // separate engine with a different list.
    let mut engine = engine_with(
        "watchlist = { enabled = true, severity = \"warning\", ouis = [\"00:11:22\"] }",
    );
    let mut aggregator = new_aggregator();

    let oui = probe_request(mac(0x0c), "example-ssid", -48, 2412);
    let alerts = engine.observe(&observe(&mut aggregator, &oui, NOW_MS), NOW_MS);
    let watchlist = of_rule(&alerts, "watchlist");
    assert_eq!(watchlist.len(), 1, "the listed OUI raises");
    assert_eq!(watchlist[0].mac, Some(mac(0x0c)));

    // A listed SSID, on an access point that is not on the MAC list.
    let mut engine = engine_with(
        "watchlist = { enabled = true, severity = \"warning\", ssids = [\"example-watched\"] }",
    );
    let mut aggregator = new_aggregator();

    let ssid = beacon_of(mac(0x15), "example-watched", -48);
    let alerts = engine.observe(&observe(&mut aggregator, &ssid, NOW_MS), NOW_MS);
    let watchlist = of_rule(&alerts, "watchlist");
    assert_eq!(watchlist.len(), 1, "the listed SSID raises");
    assert_eq!(watchlist[0].mac, Some(mac(0x15)));

    // Nothing that is not on the list.
    let other = beacon_of(mac(0x16), "example-other", -48);
    let alerts = engine.observe(
        &observe(&mut aggregator, &other, NOW_MS + 1000),
        NOW_MS + 1000,
    );
    assert!(
        of_rule(&alerts, "watchlist").is_empty(),
        "an SSID that is not on the list raises nothing"
    );
}

#[test]
fn seen_again_raises_when_the_device_comes_back_after_the_absence() {
    let mut engine =
        engine_with("seen_again = { enabled = true, severity = \"info\", after_seconds = 300 }");
    let mut aggregator = new_aggregator();

    let frame = probe_request(mac(11), "example-ssid", -48, 2412);

    // The first sighting: the device has not been seen before, so there is
    // nothing to come back to.
    let first = engine.observe(&observe(&mut aggregator, &frame, NOW_MS), NOW_MS);
    assert!(
        of_rule(&first, "seen_again").is_empty(),
        "the first sighting is not a return"
    );

    // Seen again, but before the absence has passed.
    let soon = engine.observe(
        &observe(&mut aggregator, &frame, NOW_MS + 299_000),
        NOW_MS + 299_000,
    );
    assert!(
        of_rule(&soon, "seen_again").is_empty(),
        "a short absence does not raise"
    );

    // Seen again after the absence: the device has come back.
    let later = engine.observe(
        &observe(&mut aggregator, &frame, NOW_MS + 600_000),
        NOW_MS + 600_000,
    );
    let seen_again = of_rule(&later, "seen_again");
    assert_eq!(seen_again.len(), 1, "the return raises");
    assert_eq!(seen_again[0].mac, Some(mac(11)));
}

#[test]
fn rogue_ap_raises_for_a_second_access_point_with_the_same_ssid() {
    let mut engine = engine_with("rogue_ap = { enabled = true, severity = \"warning\" }");
    let mut aggregator = new_aggregator();

    // The first access point with the name. Nothing to compare it with.
    let first = beacon_of(mac(1), "example-ssid", -48);
    let alerts = engine.observe(&observe(&mut aggregator, &first, NOW_MS), NOW_MS);
    assert!(
        of_rule(&alerts, "rogue_ap").is_empty(),
        "the first access point with a name raises nothing"
    );

    // The same access point again, with the same security.
    let again = beacon_of(mac(1), "example-ssid", -48);
    let alerts = engine.observe(
        &observe(&mut aggregator, &again, NOW_MS + 1000),
        NOW_MS + 1000,
    );
    assert!(
        of_rule(&alerts, "rogue_ap").is_empty(),
        "the same access point seen again raises nothing"
    );

    // Another access point with the same name: something else is claiming
    // the name.
    let second = beacon_of(mac(2), "example-ssid", -48);
    let alerts = engine.observe(
        &observe(&mut aggregator, &second, NOW_MS + 2000),
        NOW_MS + 2000,
    );
    let rogue = of_rule(&alerts, "rogue_ap");
    assert_eq!(rogue.len(), 1, "the second access point raises");
    assert_eq!(rogue[0].severity, Severity::Warning);
    assert_eq!(rogue[0].mac, Some(mac(2)));

    // The same name with different security.
    let other_security = beacon(mac(1), "example-ssid", 2412, -48, false);
    let alerts = engine.observe(
        &observe(&mut aggregator, &other_security, NOW_MS + 3000),
        NOW_MS + 3000,
    );
    let rogue = of_rule(&alerts, "rogue_ap");
    assert_eq!(rogue.len(), 1, "the same name with other security raises");
    assert_eq!(rogue[0].mac, Some(mac(1)));
}

#[test]
fn strong_signal_raises_for_a_stronger_signal_and_not_for_a_weaker_one() {
    let mut engine =
        engine_with("strong_signal = { enabled = true, severity = \"info\", rssi_above = -40 }");
    let mut aggregator = new_aggregator();

    // -35 dBm is stronger than -40 dBm.
    let strong = beacon_of(mac(1), "example-strong", -35);
    let alerts = engine.observe(&observe(&mut aggregator, &strong, NOW_MS), NOW_MS);
    let alerts = of_rule(&alerts, "strong_signal");
    assert_eq!(alerts.len(), 1, "the strong signal raises");
    assert_eq!(alerts[0].mac, Some(mac(1)));

    // -80 dBm is weaker than -40 dBm.
    let weak = beacon_of(mac(2), "example-weak", -80);
    let alerts = engine.observe(
        &observe(&mut aggregator, &weak, NOW_MS + 1000),
        NOW_MS + 1000,
    );
    assert!(
        of_rule(&alerts, "strong_signal").is_empty(),
        "the weak signal raises nothing"
    );
}

#[test]
fn deauth_burst_raises_when_the_count_is_reached_inside_the_window() {
    let mut engine = engine_with(
        "deauth_burst = { enabled = true, severity = \"warning\", count = 5, within_seconds = 10 }",
    );
    let mut aggregator = new_aggregator();

    // Five deauthentication frames about the same station inside ten
    // seconds.
    let mut burst = Vec::new();
    for index in 0..5 {
        let ts = NOW_MS + i64::from(index) * 1000;
        let frame = deauth_frame(mac(1), mac(21), 7);
        burst.extend(engine.observe(&observe(&mut aggregator, &frame, ts), ts));
    }

    let alerts = of_rule(&burst, "deauth_burst");
    assert_eq!(alerts.len(), 1, "the burst raises once");
    assert_eq!(alerts[0].severity, Severity::Warning);
    assert_eq!(alerts[0].mac, Some(mac(21)));

    // The same five frames, spread further apart in time.
    let mut engine = engine_with(
        "deauth_burst = { enabled = true, severity = \"warning\", count = 5, within_seconds = 10 }",
    );
    let mut aggregator = new_aggregator();
    let mut spread = Vec::new();
    for index in 0..5 {
        let ts = NOW_MS + i64::from(index) * 30_000;
        let frame = deauth_frame(mac(1), mac(21), 7);
        spread.extend(engine.observe(&observe(&mut aggregator, &frame, ts), ts));
    }
    assert!(
        of_rule(&spread, "deauth_burst").is_empty(),
        "frames spread further apart do not make a burst"
    );
}

#[test]
fn a_disabled_rule_raises_nothing() {
    let mut engine = engine_with("new_device = { enabled = false, severity = \"warning\" }");
    let mut aggregator = new_aggregator();

    let frame = probe_request(mac(11), "example-ssid", -48, 2412);
    let alerts = engine.observe(&observe(&mut aggregator, &frame, NOW_MS), NOW_MS);
    assert!(alerts.is_empty(), "a rule that is off raises nothing");
}

#[test]
fn a_configuration_that_cannot_be_parsed_is_an_error() {
    // Not TOML at all.
    assert!(Rules::parse("this is not toml").is_err());

    // A rule that is not a table.
    assert!(Rules::parse("new_device = 7").is_err());

    // A severity that is not one of the three.
    assert!(Rules::parse("new_device = { enabled = true, severity = \"loud\" }").is_err());

    // A parameter that is the wrong type.
    assert!(
        Rules::parse(
            "strong_signal = { enabled = true, severity = \"info\", rssi_above = \"loud\" }"
        )
        .is_err()
    );
    assert!(
        Rules::parse("deauth_burst = { enabled = true, severity = \"info\", count = 5 }").is_err()
    );

    // The whole engine off.
    let mut engine = engine_with("enabled = false");
    let mut aggregator = new_aggregator();
    let frame = probe_request(mac(11), "example-ssid", -48, 2412);
    let alerts = engine.observe(&observe(&mut aggregator, &frame, NOW_MS), NOW_MS);
    assert!(alerts.is_empty(), "the engine being off raises nothing");
}

#[test]
fn the_engine_tables_are_bounded() {
    // A small engine, so that the test is quick.
    let rules = parsed("new_device = { enabled = true, severity = \"info\" }");
    let mut engine = AlertEngine::with_limits(rules, 16, 4);
    let mut aggregator = Aggregator::new(1024);

    for index in 0..64u8 {
        let frame = probe_request(mac(index), "example-ssid", -48, 2412);
        let observation = observe(&mut aggregator, &frame, NOW_MS + i64::from(index));
        engine.observe(&observation, NOW_MS + i64::from(index));
    }

    assert_eq!(
        engine.device_count(),
        16,
        "the device table is capped at its limit"
    );

    // The access point table is capped too.
    let rules = parsed("rogue_ap = { enabled = true, severity = \"warning\" }");
    let mut engine = AlertEngine::with_limits(rules, 16, 4);
    let mut aggregator = Aggregator::new(1024);

    for index in 0..64u8 {
        let frame = beacon_of(mac(index), &format!("example-ssid-{index}"), -48);
        let observation = observe(&mut aggregator, &frame, NOW_MS + i64::from(index));
        engine.observe(&observation, NOW_MS + i64::from(index));
    }

    assert_eq!(
        engine.access_point_count(),
        4,
        "the access point table is capped at its limit"
    );
}

#[test]
fn an_alert_carries_the_rule_the_severity_the_mac_the_summary_and_the_details() {
    let mut engine = engine_with("new_device = { enabled = true, severity = \"critical\" }");
    let mut aggregator = new_aggregator();

    let frame = beacon_with_akm(mac(1), "example-ssid", 2412, -42, &[AKM_SAE]);
    let alerts = engine.observe(&observe(&mut aggregator, &frame, NOW_MS), NOW_MS);
    assert_eq!(alerts.len(), 1);

    let alert = &alerts[0];
    assert_eq!(alert.rule, "new_device");
    assert_eq!(alert.severity, Severity::Critical);
    assert_eq!(alert.mac, Some(mac(1)));
    assert!(
        alert.summary.contains("00:11:22:33:44:01"),
        "the summary names the device: {}",
        alert.summary
    );
    assert!(
        alert.details.is_object(),
        "the details are a JSON object: {}",
        alert.details
    );
    assert_eq!(
        alert.details["kind"],
        serde_json::Value::String("ap".to_string()),
        "the details keep what is worth keeping"
    );
    assert_eq!(
        alert.details["oui"],
        serde_json::Value::String("00:11:22".to_string())
    );
}

#[test]
fn the_summary_of_the_rules_reads_as_a_line() {
    let rules = parsed(
        "enabled = true\n\
         new_device = { enabled = true, severity = \"info\" }\n\
         watchlist = { enabled = true, severity = \"warning\", macs = [\"00:11:22:33:44:ff\"] }\n",
    );
    let summary = rules.summary();
    assert!(summary.contains("new_device"), "{summary}");
    assert!(summary.contains("watchlist"), "{summary}");
    assert!(summary.contains("warning"), "{summary}");
}

#[test]
fn the_configuration_of_the_contract_parses() {
    // The exact configuration the contract gives.
    let text = "\
enabled = true

new_device = { enabled = true, severity = \"info\" }

watchlist = {
    enabled = true,
    severity = \"warning\",
    macs = [\"00:11:22:33:44:ff\"],
    ouis = [\"00:11:22\"],
    ssids = [\"example-ssid\"],
}

seen_again = { enabled = true, severity = \"info\", after_seconds = 300 }

rogue_ap = { enabled = true, severity = \"warning\" }

strong_signal = { enabled = true, severity = \"info\", rssi_above = -40 }

deauth_burst = { enabled = true, severity = \"warning\", count = 5, within_seconds = 10 }
";
    let rules = parsed(text);
    assert!(rules.enabled);
    assert_eq!(
        rules.new_device.as_ref().expect("new_device").severity,
        Severity::Info
    );
    assert_eq!(
        rules.watchlist.as_ref().expect("watchlist").severity,
        Severity::Warning
    );
    assert_eq!(rules.watchlist.as_ref().expect("watchlist").macs.len(), 1);
    assert_eq!(rules.watchlist.as_ref().expect("watchlist").ouis.len(), 1);
    assert_eq!(rules.watchlist.as_ref().expect("watchlist").ssids.len(), 1);
    assert_eq!(
        rules.seen_again.as_ref().expect("seen_again").after_seconds,
        300
    );
    assert_eq!(
        rules.rogue_ap.as_ref().expect("rogue_ap").severity,
        Severity::Warning
    );
    assert_eq!(
        rules
            .strong_signal
            .as_ref()
            .expect("strong_signal")
            .rssi_above,
        -40
    );
    assert_eq!(rules.deauth_burst.as_ref().expect("deauth_burst").count, 5);
    assert_eq!(
        rules
            .deauth_burst
            .as_ref()
            .expect("deauth_burst")
            .within_seconds,
        10
    );
}

#[test]
fn the_watchlist_matches_the_mac_and_the_oui_in_lower_case_with_colons() {
    let rules = parsed(
        "watchlist = { enabled = true, severity = \"warning\", \
         macs = [\"00:11:22:33:44:0b\"], ouis = [\"00:11:22\"] }",
    );
    let watchlist = rules.watchlist.expect("watchlist");

    assert!(watchlist.matches_mac(mac(0x0b)), "the listed MAC matches");
    assert!(
        watchlist.matches_mac(mac(0x0c)),
        "the listed OUI matches too"
    );
    assert!(!watchlist.matches_mac([0xaa, 0xbb, 0xcc, 0x00, 0x01, 0x02]));
}

#[test]
fn the_watchlist_matches_the_ssid_as_bytes() {
    let rules = parsed(
        "watchlist = { enabled = true, severity = \"warning\", ssids = [\"example-ssid\"] }",
    );
    let watchlist = rules.watchlist.expect("watchlist");

    assert!(watchlist.matches_ssid(b"example-ssid"));
    assert!(!watchlist.matches_ssid(b"example-ssid-2"));
    assert!(!watchlist.matches_ssid(b"example-ssid\0"));
    assert!(
        !watchlist.matches_ssid(b"example-SSID"),
        "the match is exact, as bytes"
    );
}

#[test]
fn an_empty_configuration_means_every_rule_is_off() {
    let rules = parsed(NOTHING);
    assert!(rules.new_device.is_none());
    assert!(rules.watchlist.is_none());
    assert!(rules.seen_again.is_none());
    assert!(rules.rogue_ap.is_none());
    assert!(rules.strong_signal.is_none());
    assert!(rules.deauth_burst.is_none());

    let mut engine = AlertEngine::new(rules);
    let mut aggregator = new_aggregator();
    let frame = probe_request(mac(11), "example-ssid", -48, 2412);
    let alerts = engine.observe(&observe(&mut aggregator, &frame, NOW_MS), NOW_MS);
    assert!(alerts.is_empty());
}

#[test]
fn the_akm_suites_are_only_used_to_tell_the_networks_apart() {
    // A WPA2 network and a WPA3 network with the same name, on different
    // access points: the second one is another access point claiming the
    // name.
    let mut engine = engine_with("rogue_ap = { enabled = true, severity = \"warning\" }");
    let mut aggregator = new_aggregator();

    let wpa2 = beacon_with_akm(mac(1), "example-ssid", 2412, -42, &[AKM_PSK]);
    let alerts = engine.observe(&observe(&mut aggregator, &wpa2, NOW_MS), NOW_MS);
    assert!(of_rule(&alerts, "rogue_ap").is_empty());

    let wpa3 = beacon_with_akm(mac(2), "example-ssid", 2412, -42, &[AKM_SAE]);
    let alerts = engine.observe(
        &observe(&mut aggregator, &wpa3, NOW_MS + 1000),
        NOW_MS + 1000,
    );
    assert_eq!(of_rule(&alerts, "rogue_ap").len(), 1);
}
