//! Strict RFC5280 section4.1.2.5 certificate time decoding.
//! Signed seconds also represent pre-1970 certificate dates without wrapping.
use super::der::InvalidDer;
pub fn parse(tag: u8, value: &[u8]) -> Result<i64, InvalidDer> {
    let (year, offset) = match tag {
        0x17 if value.len() == 13 => {
            let year = digits(&value[..2])?;
            (if year >= 50 { 1900 + year } else { 2000 + year }, 2)
        }
        0x18 if value.len() == 15 => {
            let year = digits(&value[..4])?;
            // RFC5280 requires UTCTime through 2049.
            if year < 2050 {
                return Err(InvalidDer);
            }
            (year, 4)
        }
        _ => return Err(InvalidDer),
    };
    if value.last() != Some(&b'Z') {
        return Err(InvalidDer);
    }
    let month = digits(&value[offset..offset + 2])?;
    let day = digits(&value[offset + 2..offset + 4])?;
    let hour = digits(&value[offset + 4..offset + 6])?;
    let minute = digits(&value[offset + 6..offset + 8])?;
    let second = digits(&value[offset + 8..offset + 10])?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day < 1
        || day > months[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(InvalidDer);
    }
    let days_before = |y: i64| 365 * (y - 1) + (y - 1) / 4 - (y - 1) / 100 + (y - 1) / 400;
    let days = days_before(year) - days_before(1970)
        + months[..(month - 1) as usize].iter().sum::<i64>()
        + day
        - 1;
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}
fn digits(value: &[u8]) -> Result<i64, InvalidDer> {
    value.iter().try_fold(0, |n, &c| {
        if c.is_ascii_digit() {
            Ok(n * 10 + i64::from(c - b'0'))
        } else {
            Err(InvalidDer)
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn epoch_centuries_and_leap_days() {
        assert_eq!(parse(0x17, b"700101000000Z"), Ok(0));
        assert_eq!(parse(0x17, b"691231235959Z"), Ok(-1));
        assert_eq!(parse(0x17, b"500101000000Z"), Ok(-631152000));
        assert_eq!(parse(0x18, b"20500101000000Z"), Ok(2524608000));
        assert!(parse(0x17, b"000229000000Z").is_ok());
        assert!(parse(0x18, b"21000229000000Z").is_err());
        assert!(parse(0x18, b"24000229000000Z").is_ok());
    }
    #[test]
    fn rejects_offsets_fractions_invalid_dates_and_noncanonical_years() {
        for value in [
            &b"250229000000Z"[..],
            b"251301000000Z",
            b"250101240000Z",
            b"250101006000Z",
            b"250101000060Z",
            b"250101000000+",
            b"2501010000Z",
            b"25010100000xZ",
        ] {
            assert!(parse(0x17, value).is_err());
        }
        assert!(parse(0x18, b"20491231235959Z").is_err());
    }
}
