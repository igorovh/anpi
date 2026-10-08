use serde_json::Value;
use serde_json_path::JsonPath;

use crate::models::ContentKind;

/// Validates the configuration when a monitor is saved, so bad input never reaches the scheduler.
pub fn validate(kind: ContentKind, value: &str) -> Result<(), String> {
    match kind {
        ContentKind::None => Ok(()),
        ContentKind::Contains | ContentKind::NotContains if value.is_empty() => Err("keyword cannot be empty".into()),
        ContentKind::Contains | ContentKind::NotContains => Ok(()),
        ContentKind::Regex => regex::Regex::new(value).map(|_| ()).map_err(|e| format!("invalid regex: {e}")),
        ContentKind::JsonPath => JsonPath::parse(value).map(|_| ()).map_err(|e| format!("invalid JSONPath: {e}")),
    }
}

pub fn evaluate(kind: ContentKind, value: &str, expected: &str, body: &str) -> Result<(), String> {
    match kind {
        ContentKind::None => Ok(()),
        ContentKind::Contains if body.contains(value) => Ok(()),
        ContentKind::Contains => Err(format!("keyword \"{value}\" not found in response")),
        ContentKind::NotContains if body.contains(value) => Err(format!("forbidden keyword \"{value}\" found in response")),
        ContentKind::NotContains => Ok(()),
        ContentKind::Regex => {
            let re = regex::Regex::new(value).map_err(|e| format!("invalid regex: {e}"))?;
            if re.is_match(body) { Ok(()) } else { Err(format!("regex /{value}/ did not match response")) }
        }
        ContentKind::JsonPath => {
            let json: Value = serde_json::from_str(body).map_err(|_| "response is not valid JSON".to_string())?;
            let path = JsonPath::parse(value).map_err(|e| format!("invalid JSONPath: {e}"))?;
            let nodes = path.query(&json).all();
            if nodes.is_empty() {
                return Err(format!("JSONPath {value} matched nothing"));
            }
            if expected.is_empty() || nodes.iter().any(|n| json_equals(n, expected)) {
                return Ok(());
            }
            let got = nodes.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");
            Err(format!("JSONPath {value} = {got}, expected {expected}"))
        }
    }
}

fn json_equals(node: &Value, expected: &str) -> bool {
    match node {
        Value::String(s) => s == expected,
        Value::Number(n) => match (n.as_f64(), expected.trim().parse::<f64>()) {
            (Some(a), Ok(b)) => a == b,
            _ => false,
        },
        Value::Bool(b) => expected.trim().eq_ignore_ascii_case(if *b { "true" } else { "false" }),
        Value::Null => expected.trim() == "null",
        other => serde_json::from_str::<Value>(expected.trim()).is_ok_and(|e| &e == other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ContentKind::*;

    const BODY: &str = r#"{"status":"ok","db":{"healthy":true,"latency":12},"items":[{"id":1},{"id":2}],"version":"1.2"}"#;

    #[test]
    fn keyword_presence_and_absence() {
        assert!(evaluate(Contains, "\"ok\"", "", BODY).is_ok());
        assert!(evaluate(Contains, "error", "", BODY).unwrap_err().contains("not found"));
        assert!(evaluate(NotContains, "error", "", BODY).is_ok());
        assert!(evaluate(NotContains, "healthy", "", BODY).unwrap_err().contains("forbidden"));
    }

    #[test]
    fn regex_match() {
        assert!(evaluate(Regex, r#""latency":\d+"#, "", BODY).is_ok());
        assert!(evaluate(Regex, r"^<html", "", BODY).is_err());
    }

    #[test]
    fn json_path_existence_and_typed_comparisons() {
        assert!(evaluate(JsonPath, "$.db.healthy", "", BODY).is_ok());
        assert!(evaluate(JsonPath, "$.status", "ok", BODY).is_ok());
        assert!(evaluate(JsonPath, "$.db.healthy", "true", BODY).is_ok());
        assert!(evaluate(JsonPath, "$.db.latency", "12.0", BODY).is_ok());
        assert!(evaluate(JsonPath, "$.items[*].id", "2", BODY).is_ok(), "any matching node passes");
        assert!(evaluate(JsonPath, "$.version", "1.2", BODY).is_ok());
        assert!(evaluate(JsonPath, "$.version", "1.20", BODY).is_err(), "strings compare exactly");
    }

    #[test]
    fn json_path_failures_explain_why() {
        let e = evaluate(JsonPath, "$.status", "degraded", BODY).unwrap_err();
        assert!(e.contains("\"ok\"") && e.contains("degraded"), "{e}");
        assert!(evaluate(JsonPath, "$.missing", "", BODY).unwrap_err().contains("matched nothing"));
        assert!(evaluate(JsonPath, "$.status", "", "<html>").unwrap_err().contains("not valid JSON"));
        assert!(evaluate(JsonPath, "$.db.healthy", "false", BODY).is_err());
    }

    #[test]
    fn validation_catches_bad_config() {
        assert!(validate(Regex, "(unclosed").is_err());
        assert!(validate(JsonPath, "status").is_err());
        assert!(validate(JsonPath, "$.status").is_ok());
        assert!(validate(Contains, "").is_err());
        assert!(validate(None, "").is_ok());
    }
}
