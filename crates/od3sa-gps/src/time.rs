//! Parsing the timestamp gpsd sends.
//!
//! gpsd sends the time of a fix as an ISO-8601 string, for example
//! `2026-11-05T09:00:00Z`. The crate has no date-time dependency, so the
//! handful of forms gpsd uses are parsed here by hand.

/// Parse an ISO-8601 timestamp into unix epoch milliseconds.
///
/// Accepted forms are `YYYY-MM-DD` followed by `T`, `t` or a space, then
/// `HH:MM:SS`, an optional fractional second and an optional UTC offset
/// (`Z`, `+HH:MM`, `-HHMM`). A timestamp without an offset is read as UTC.
///
/// Returns `None` when the string is not one of those forms. A message with
/// an unreadable timestamp is not an error: the fix is kept and the time is
/// left at zero.
pub(crate) fn parse_iso8601_ms(text: &str) -> Option<i64> {
    let s = text.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return None;
    }

    let year: i64 = s.get(0..4)?.parse().ok()?;
    if bytes[4] != b'-' {
        return None;
    }
    let month: i64 = s.get(5..7)?.parse().ok()?;
    if bytes[7] != b'-' {
        return None;
    }
    let day: i64 = s.get(8..10)?.parse().ok()?;
    if !matches!(bytes[10], b'T' | b't' | b' ') {
        return None;
    }
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    if bytes[13] != b':' {
        return None;
    }
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    if bytes[16] != b':' {
        return None;
    }
    let second: i64 = s.get(17..19)?.parse().ok()?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let mut rest = &s[19..];
    let mut millis: i64 = 0;
    if let Some(after) = rest.strip_prefix('.') {
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let mut padded = digits.clone();
        while padded.len() < 3 {
            padded.push('0');
        }
        millis = padded.get(0..3)?.parse().ok()?;
        rest = after.get(digits.len()..)?;
    }

    let offset_secs = parse_offset(rest)?;
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second - offset_secs;
    Some(secs * 1_000 + millis)
}

/// The UTC offset of a timestamp, in seconds east of Greenwich.
fn parse_offset(rest: &str) -> Option<i64> {
    if rest.is_empty() || rest == "Z" || rest == "z" {
        return Some(0);
    }
    let sign = match rest.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let offset = &rest[1..];
    let (hours, minutes) = if offset.len() == 5 && offset.as_bytes()[2] == b':' {
        (offset.get(0..2)?, offset.get(3..5)?)
    } else if offset.len() == 4 {
        (offset.get(0..2)?, offset.get(2..4)?)
    } else {
        return None;
    };
    let hours: i64 = hours.parse().ok()?;
    let minutes: i64 = minutes.parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3_600 + minutes * 60))
}

/// The number of days between the epoch and a civil date.
///
/// This is Howard Hinnant's `days_from_civil`, the usual proleptic
/// Gregorian day count.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::parse_iso8601_ms;

    #[test]
    fn reads_the_epoch_itself() {
        assert_eq!(parse_iso8601_ms("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn reads_a_leap_day() {
        // 2024-02-29T12:00:00Z is 1_709_208_000 seconds after the epoch.
        assert_eq!(
            parse_iso8601_ms("2024-02-29T12:00:00Z"),
            Some(1_709_208_000_000)
        );
    }

    #[test]
    fn reads_fractional_seconds() {
        assert_eq!(
            parse_iso8601_ms("2024-02-29T12:00:00.250Z"),
            Some(1_709_208_000_250)
        );
    }

    #[test]
    fn reads_an_offset() {
        assert_eq!(
            parse_iso8601_ms("2024-02-29T14:00:00+02:00"),
            Some(1_709_208_000_000)
        );
        assert_eq!(
            parse_iso8601_ms("2024-02-29T07:00:00-0500"),
            Some(1_709_208_000_000)
        );
    }

    #[test]
    fn rejects_rubbish() {
        assert_eq!(parse_iso8601_ms(""), None);
        assert_eq!(parse_iso8601_ms("not a time"), None);
        assert_eq!(parse_iso8601_ms("2024-13-01T00:00:00Z"), None);
        assert_eq!(
            parse_iso8601_ms("2024-02-29 12:00:00Z"),
            Some(1_709_208_000_000)
        );
    }
}
