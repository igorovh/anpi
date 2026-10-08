use std::fmt::Write;

use crate::stats::Point;
use crate::util::{format_ms, format_ts_short};

const W: f64 = 800.0;
const H: f64 = 220.0;
const PAD_L: f64 = 52.0;
const PAD_R: f64 = 8.0;
const PAD_T: f64 = 10.0;
const PAD_B: f64 = 26.0;

pub const PHASES: [(&str, &str); 5] =
    [("ph-dns", "DNS"), ("ph-connect", "Connect"), ("ph-tls", "TLS"), ("ph-ttfb", "Server wait"), ("ph-transfer", "Transfer")];

/// Splits a point's total into the five phases; non-HTTP monitors put everything into "wait".
fn layers(p: &Point) -> Option<[f64; 5]> {
    let total = p.total_ms?;
    let dns = p.dns_ms.unwrap_or(0.0);
    let connect = p.connect_ms.unwrap_or(0.0);
    let tls = p.tls_ms.unwrap_or(0.0);
    let ttfb = p.ttfb_ms.unwrap_or(0.0);
    if dns + connect + tls + ttfb == 0.0 {
        return Some([0.0, 0.0, 0.0, total, 0.0]);
    }
    let transfer = (total - dns - connect - tls - ttfb).max(0.0);
    Some([dns, connect, tls, ttfb, transfer])
}

fn nice_ceiling(v: f64) -> f64 {
    if v <= 0.0 {
        return 100.0;
    }
    let mag = 10f64.powf(v.log10().floor());
    for m in [1.0, 2.0, 2.5, 5.0, 10.0] {
        if v <= m * mag {
            return m * mag;
        }
    }
    10.0 * mag
}

pub fn latency_svg(points: &[Point], since: i64, until: i64, bucket_ms: i64) -> String {
    let span = (until - since).max(1) as f64;
    let x = |t: i64| PAD_L + (t - since) as f64 / span * (W - PAD_L - PAD_R);
    let max = points.iter().filter_map(|p| p.total_ms).fold(0.0, f64::max);
    let y_max = nice_ceiling(max * 1.05);
    let y = |v: f64| H - PAD_B - (v / y_max) * (H - PAD_T - PAD_B);

    let mut svg = String::new();
    let _ = write!(svg, r#"<svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="Response time chart" preserveAspectRatio="none">"#);
    for i in 0..=4 {
        let v = y_max * i as f64 / 4.0;
        let yy = y(v);
        let _ = write!(svg, r#"<line class="grid" x1="{PAD_L}" x2="{}" y1="{yy:.1}" y2="{yy:.1}"/>"#, W - PAD_R);
        let _ = write!(svg, r#"<text class="axis" x="{}" y="{:.1}" text-anchor="end">{}</text>"#, PAD_L - 6.0, yy + 4.0, format_ms(Some(v)));
    }
    for i in 0..=4 {
        let t = since + ((until - since) as f64 * i as f64 / 4.0) as i64;
        let anchor = match i {
            0 => "start",
            4 => "end",
            _ => "middle",
        };
        let _ = write!(svg, r#"<text class="axis" x="{:.1}" y="{}" text-anchor="{anchor}">{}</text>"#, x(t), H - 8.0, format_ts_short(t));
    }

    // Consecutive buckets form a segment; a gap in data breaks the area instead of bridging it.
    let mut segments: Vec<Vec<(f64, [f64; 5])>> = Vec::new();
    let mut last_t: Option<i64> = None;
    for p in points {
        let Some(l) = layers(p) else {
            last_t = None;
            continue;
        };
        let x0 = x(p.t + bucket_ms / 2);
        match (segments.last_mut(), last_t) {
            (Some(seg), Some(lt)) if p.t - lt <= bucket_ms * 2 => seg.push((x0, l)),
            _ => segments.push(vec![(x0, l)]),
        }
        last_t = Some(p.t);
    }
    for (layer, (class, _)) in PHASES.iter().enumerate() {
        if segments.iter().flatten().all(|(_, l)| l[layer] == 0.0) {
            continue;
        }
        let mut d = String::new();
        for seg in &segments {
            let top: Vec<(f64, f64)> = seg.iter().map(|(xx, l)| (*xx, l[..=layer].iter().sum())).collect();
            let bottom: Vec<(f64, f64)> = seg.iter().map(|(xx, l)| (*xx, l[..layer].iter().sum())).collect();
            if seg.len() == 1 {
                let (xx, t) = top[0];
                let b = bottom[0].1;
                let _ = write!(d, "M{:.1},{:.1}L{:.1},{:.1}L{:.1},{:.1}L{:.1},{:.1}Z", xx - 2.0, y(b), xx - 2.0, y(t), xx + 2.0, y(t), xx + 2.0, y(b));
                continue;
            }
            for (i, (xx, v)) in top.iter().enumerate() {
                let _ = write!(d, "{}{:.1},{:.1}", if i == 0 { "M" } else { "L" }, xx, y(*v));
            }
            for (xx, v) in bottom.iter().rev() {
                let _ = write!(d, "L{:.1},{:.1}", xx, y(*v));
            }
            d.push('Z');
        }
        if !d.is_empty() {
            let _ = write!(svg, r#"<path class="area {class}" d="{d}"/>"#);
        }
    }
    let bw = ((bucket_ms as f64 / span) * (W - PAD_L - PAD_R)).max(2.0);
    for p in points.iter().filter(|p| p.down > 0) {
        let _ = write!(svg, r#"<rect class="down-mark" x="{:.1}" y="{}" width="{bw:.1}" height="4"/>"#, x(p.t), H - PAD_B + 2.0);
    }
    if segments.is_empty() {
        let _ = write!(svg, r#"<text class="axis empty" x="{}" y="{}" text-anchor="middle">No data in this range yet</text>"#, W / 2.0, H / 2.0);
    }
    svg.push_str("</svg>");
    svg
}

pub struct PhaseAvg {
    pub class: &'static str,
    pub label: &'static str,
    pub value: String,
}

/// Average split of response time across phases, weighted by successful checks.
pub fn phase_breakdown(points: &[Point]) -> (String, Vec<PhaseAvg>) {
    let mut sums = [0.0f64; 5];
    let mut weight = 0.0;
    for p in points {
        if let Some(l) = layers(p) {
            let w = p.up.max(1) as f64;
            for (s, v) in sums.iter_mut().zip(l) {
                *s += v * w;
            }
            weight += w;
        }
    }
    if weight == 0.0 {
        return (String::new(), Vec::new());
    }
    let avgs: Vec<f64> = sums.iter().map(|s| s / weight).collect();
    let total: f64 = avgs.iter().sum();
    let mut svg = String::from(r#"<svg class="phasebar" viewBox="0 0 800 14" preserveAspectRatio="none" role="img" aria-label="Average time per phase">"#);
    let mut xpos = 0.0;
    let mut legend = Vec::new();
    for ((class, label), v) in PHASES.iter().zip(&avgs) {
        if *v <= 0.0 {
            continue;
        }
        let w = v / total.max(f64::EPSILON) * 800.0;
        let _ = write!(svg, r#"<rect class="{class}" x="{xpos:.1}" y="0" width="{w:.1}" height="14"/>"#);
        xpos += w;
        legend.push(PhaseAvg { class, label, value: format_ms(Some(*v)) });
    }
    svg.push_str("</svg>");
    (svg, legend)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(t: i64, total: Option<f64>, phases: Option<[f64; 4]>, down: i64) -> Point {
        let [dns, connect, tls, ttfb] = phases.map(|p| p.map(Some)).unwrap_or([None; 4]);
        Point { t, total_ms: total, dns_ms: dns, connect_ms: connect, tls_ms: tls, ttfb_ms: ttfb, up: 1, down }
    }

    #[test]
    fn phases_add_up_to_total_and_never_go_negative() {
        let l = layers(&pt(0, Some(100.0), Some([10.0, 20.0, 30.0, 25.0]), 0)).unwrap();
        assert_eq!(l, [10.0, 20.0, 30.0, 25.0, 15.0]);
        let l = layers(&pt(0, Some(50.0), Some([10.0, 20.0, 30.0, 25.0]), 0)).unwrap();
        assert_eq!(l[4], 0.0);
        assert_eq!(layers(&pt(0, Some(42.0), None, 0)).unwrap(), [0.0, 0.0, 0.0, 42.0, 0.0]);
        assert!(layers(&pt(0, None, None, 1)).is_none());
    }

    #[test]
    fn axis_scale_is_rounded() {
        assert_eq!(nice_ceiling(87.0), 100.0);
        assert_eq!(nice_ceiling(130.0), 200.0);
        assert_eq!(nice_ceiling(2300.0), 2500.0);
        assert_eq!(nice_ceiling(0.0), 100.0);
    }

    #[test]
    fn svg_marks_downtime_and_handles_empty_data() {
        let pts = vec![pt(0, Some(10.0), None, 0), pt(60, None, None, 3), pt(120, Some(12.0), None, 0)];
        let svg = latency_svg(&pts, 0, 180, 60);
        assert!(svg.contains("down-mark"));
        assert_eq!(svg.matches("<path").count(), 1, "only the non-empty layer is drawn");
        assert!(latency_svg(&[], 0, 100, 10).contains("No data"));
        assert!(!svg.contains("NaN"));
    }

    #[test]
    fn breakdown_weights_by_check_count() {
        let mut a = pt(0, Some(100.0), Some([0.0, 0.0, 0.0, 100.0]), 0);
        a.up = 3;
        let b = pt(1, Some(20.0), Some([0.0, 0.0, 0.0, 20.0]), 0);
        let (_, legend) = phase_breakdown(&[a, b]);
        assert_eq!(legend.len(), 1);
        assert_eq!(legend[0].value, "80 ms");
    }
}
