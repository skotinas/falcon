#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizeReport {
    pub format: &'static str,
    pub bytes_removed: usize,
    pub segments_stripped: usize,
}

/// Strips EXIF/GPS/comment metadata from JPEG and ancillary metadata chunks from PNG
/// without re-encoding image pixel data. Non-image files are returned untouched.
pub fn sanitize_file_bytes(input: &[u8]) -> (Vec<u8>, SanitizeReport) {
    if input.len() >= 4 && input[0] == 0xFF && input[1] == 0xD8 {
        return strip_jpeg_metadata(input);
    }
    if input.len() >= 8 && &input[0..8] == b"\x89PNG\r\n\x1a\n" {
        return strip_png_metadata(input);
    }
    (
        input.to_vec(),
        SanitizeReport {
            format: "raw",
            bytes_removed: 0,
            segments_stripped: 0,
        },
    )
}

fn strip_jpeg_metadata(data: &[u8]) -> (Vec<u8>, SanitizeReport) {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[0..2]); // SOI (0xFF 0xD8)

    let mut i = 2usize;
    let mut stripped = 0usize;

    while i + 1 < data.len() {
        if data[i] != 0xFF {
            // Unexpected byte before SOS; bail cleanly and preserve original
            return fallback_raw(data, "jpeg-unmodified");
        }
        // Skip fill 0xFF bytes
        while i + 1 < data.len() && data[i + 1] == 0xFF {
            i += 1;
        }
        if i + 1 >= data.len() {
            break;
        }
        let marker = data[i + 1];

        // Start of Scan (0xDA) or End of Image (0xD9): copy rest verbatim
        if marker == 0xDA || marker == 0xD9 {
            out.extend_from_slice(&data[i..]);
            break;
        }

        // Standalone markers without length
        if (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            out.extend_from_slice(&data[i..i + 2]);
            i += 2;
            continue;
        }

        if i + 4 > data.len() {
            return fallback_raw(data, "jpeg-unmodified");
        }
        let seg_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        let seg_end = match i.checked_add(2).and_then(|v| v.checked_add(seg_len)) {
            Some(end) if seg_len >= 2 && end <= data.len() => end,
            _ => return fallback_raw(data, "jpeg-unmodified"),
        };

        // Strip APP1..APP15 (EXIF, XMP, ICC, GPS, Adobe) and COM (0xFE) comments.
        // Keep APP0 (JFIF) and all quantization/Huffman/frame tables intact.
        let is_metadata = (0xE1..=0xEF).contains(&marker) || marker == 0xFE;
        if is_metadata {
            stripped += 1;
        } else {
            out.extend_from_slice(&data[i..seg_end]);
        }
        i = seg_end;
    }

    let removed = data.len().saturating_sub(out.len());
    (
        out,
        SanitizeReport {
            format: "jpeg",
            bytes_removed: removed,
            segments_stripped: stripped,
        },
    )
}

fn strip_png_metadata(data: &[u8]) -> (Vec<u8>, SanitizeReport) {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[0..8]); // PNG signature

    let mut i = 8usize;
    let mut stripped = 0usize;
    let mut saw_iend = false;

    while i + 12 <= data.len() {
        let len = u32::from_be_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        let chunk_end = match i.checked_add(12).and_then(|v| v.checked_add(len)) {
            Some(end) if end <= data.len() => end,
            _ => return fallback_raw(data, "png-unmodified"),
        };
        let chunk_type = &data[i + 4..i + 8];

        // Keep critical chunks (uppercase first byte) plus transparency (tRNS).
        // Strip ancillary metadata (eXIf, tEXt, iTXt, zTXt, tIME, pHYs, etc.).
        let is_critical = (chunk_type[0] & 0x20) == 0;
        let keep = is_critical || chunk_type == b"tRNS";
        if keep {
            out.extend_from_slice(&data[i..chunk_end]);
        } else {
            stripped += 1;
        }
        i = chunk_end;
        if chunk_type == b"IEND" {
            saw_iend = true;
            break;
        }
    }

    if !saw_iend {
        return fallback_raw(data, "png-unmodified");
    }

    let removed = data.len().saturating_sub(out.len());
    (
        out,
        SanitizeReport {
            format: "png",
            bytes_removed: removed,
            segments_stripped: stripped,
        },
    )
}

fn fallback_raw(data: &[u8], fmt: &'static str) -> (Vec<u8>, SanitizeReport) {
    (
        data.to_vec(),
        SanitizeReport {
            format: fmt,
            bytes_removed: 0,
            segments_stripped: 0,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_jpeg_exif_and_com_segments() {
        let mut jpg = Vec::new();
        jpg.extend_from_slice(&[0xFF, 0xD8]); // SOI
                                              // APP1 EXIF segment with fake GPS string
        let exif = b"Exif\0\0GPS:37.9838N,23.7275E";
        jpg.extend_from_slice(&[0xFF, 0xE1]);
        jpg.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
        jpg.extend_from_slice(exif);
        // COM segment
        let com = b"CameraModel:Test";
        jpg.extend_from_slice(&[0xFF, 0xFE]);
        jpg.extend_from_slice(&((com.len() + 2) as u16).to_be_bytes());
        jpg.extend_from_slice(com);
        // SOS + dummy pixel stream + EOI
        jpg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0x11, 0x22, 0xFF, 0xD9]);

        let (clean, rep) = sanitize_file_bytes(&jpg);
        assert_eq!(rep.format, "jpeg");
        assert_eq!(rep.segments_stripped, 2);
        assert!(rep.bytes_removed > 0);
        assert!(!clean.windows(3).any(|w| w == b"GPS"));
        assert_eq!(&clean[..2], &[0xFF, 0xD8]);
    }

    #[test]
    fn strips_png_text_and_exif_chunks() {
        let mut png = Vec::new();
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        // Minimal IHDR chunk (0-byte dummy for structural test)
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&[0, 0, 0, 0]); // CRC
                                              // tEXt ancillary chunk with operator info
        let txt = b"Author\0Operator-Alpha";
        png.extend_from_slice(&(txt.len() as u32).to_be_bytes());
        png.extend_from_slice(b"tEXt");
        png.extend_from_slice(txt);
        png.extend_from_slice(&[0, 0, 0, 0]);
        // IEND
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&[0, 0, 0, 0]);

        let (clean, rep) = sanitize_file_bytes(&png);
        assert_eq!(rep.format, "png");
        assert_eq!(rep.segments_stripped, 1);
        assert!(!clean.windows(8).any(|w| w == b"Operator"));
    }
}
