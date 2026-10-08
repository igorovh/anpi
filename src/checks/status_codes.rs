/// Accepted status codes like `200-299, 301, 4xx`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusMatcher {
    ranges: Vec<(u16, u16)>,
}

impl StatusMatcher {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut ranges = Vec::new();
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let lower = part.to_ascii_lowercase();
            let range = if let Some(class) = lower.strip_suffix("xx") {
                let d: u16 = class.parse().map_err(|_| format!("invalid status class '{part}'"))?;
                if !(1..=5).contains(&d) {
                    return Err(format!("invalid status class '{part}'"));
                }
                (d * 100, d * 100 + 99)
            } else if let Some((a, b)) = lower.split_once('-') {
                let a = parse_code(a.trim(), part)?;
                let b = parse_code(b.trim(), part)?;
                if a > b {
                    return Err(format!("range '{part}' is reversed"));
                }
                (a, b)
            } else {
                let c = parse_code(&lower, part)?;
                (c, c)
            };
            ranges.push(range);
        }
        if ranges.is_empty() {
            return Err("at least one status code is required".into());
        }
        Ok(Self { ranges })
    }

    pub fn matches(&self, code: u16) -> bool {
        self.ranges.iter().any(|(a, b)| (*a..=*b).contains(&code))
    }
}

fn parse_code(s: &str, part: &str) -> Result<u16, String> {
    match s.parse::<u16>() {
        Ok(c) if (100..=599).contains(&c) => Ok(c),
        _ => Err(format!("invalid status code '{part}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_success_range() {
        let m = StatusMatcher::parse("200-299").unwrap();
        assert!(m.matches(200) && m.matches(204) && m.matches(299));
        assert!(!m.matches(199) && !m.matches(300) && !m.matches(503));
    }

    #[test]
    fn mixed_list_with_classes_and_whitespace() {
        let m = StatusMatcher::parse(" 2xx , 301,404-405 ").unwrap();
        assert!(m.matches(250) && m.matches(301) && m.matches(404) && m.matches(405));
        assert!(!m.matches(302) && !m.matches(403) && !m.matches(500));
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", " , ", "abc", "99", "600", "300-200", "9xx", "2xx-3xx"] {
            assert!(StatusMatcher::parse(bad).is_err(), "should reject {bad:?}");
        }
    }
}
