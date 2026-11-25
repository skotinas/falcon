use crate::error::{CryptoError, Result};
use qrcode::render::{svg, unicode};
use qrcode::{EcLevel, QrCode};

pub fn render_terminal_qr(payload: &str) -> Result<String> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .map_err(|e| CryptoError::ShamirError(format!("QR encode failed: {e}")))?;

    let rendered = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build();
    Ok(rendered)
}

pub fn render_qr_svg(payload: &str) -> Result<String> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .map_err(|e| CryptoError::ShamirError(format!("QR encode failed: {e}")))?;

    let svg_str = code
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#11161c"))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build();
    Ok(svg_str)
}

pub fn render_keycard_svg(title: &str, subtitle: &str, payload: &str) -> Result<String> {
    let qr_raw = render_qr_svg(payload)?;
    // Strip XML declaration if present so we can nest the QR SVG cleanly
    let qr_inner = qr_raw
        .trim()
        .strip_prefix("<?xml version=\"1.0\" standalone=\"yes\"?>")
        .unwrap_or(&qr_raw)
        .trim();

    let safe_title = xml_escape(title);
    let safe_sub = xml_escape(subtitle);
    let safe_payload = xml_escape(payload);

    // Wrap long share strings into 48-char monospace lines for paper readability
    let mut lines_svg = String::new();
    for (idx, chunk) in safe_payload.as_bytes().chunks(46).enumerate() {
        let line = std::str::from_utf8(chunk).unwrap_or("");
        let y = 330 + idx * 16;
        lines_svg.push_str(&format!(
            "<text x=\"24\" y=\"{y}\" font-family=\"monospace\" font-size=\"10.5\" fill=\"#11161c\">{line}</text>\n"
        ));
    }

    Ok(format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="420" height="410" viewBox="0 0 420 410">
  <rect x="1" y="1" width="418" height="408" fill="#ffffff" stroke="#11161c" stroke-width="2"/>
  <rect x="1" y="1" width="418" height="44" fill="#11161c"/>
  <text x="20" y="21" font-family="monospace" font-size="13" font-weight="bold" fill="#d49b35" letter-spacing="2">FALCON // AIR-GAPPED KEYCARD</text>
  <text x="20" y="36" font-family="monospace" font-size="10" fill="#a8b3c2">{safe_title} · {safe_sub}</text>
  <g transform="translate(95, 62)">
    {qr_inner}
  </g>
  <line x1="20" y1="308" x2="400" y2="308" stroke="#bcc6d1" stroke-width="1"/>
  {lines_svg}
  <text x="20" y="394" font-family="monospace" font-size="9" fill="#525f6d">STORE OFFLINE IN SEPARATE CUSTODY · VERIFY BLAKE3 CHECKSUM ON RESTORE</text>
</svg>"##
    ))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_terminal_and_svg_keycard() {
        let sample = "FLCN-S1-01-03-deadbeef01020304-aabbccdd";
        let term = render_terminal_qr(sample).unwrap();
        assert!(term.lines().count() > 10);

        let card = render_keycard_svg("SHARE 01 OF 05", "THRESHOLD 3", sample).unwrap();
        assert!(card.contains("<svg"));
        assert!(card.contains("FALCON // AIR-GAPPED KEYCARD"));
        assert!(card.contains(sample));
    }
}
