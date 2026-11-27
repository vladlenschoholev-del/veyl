use std::io::Cursor;

use image::{ImageFormat, ImageReader};

use crate::{CryptoError, Result};

/// Decodes and re-encodes raster JPEG/PNG images, discarding embedded metadata.
/// Other formats are rejected rather than passed through unsanitized.
pub fn strip_image_metadata(input: &[u8]) -> Result<Vec<u8>> {
    let reader = ImageReader::new(Cursor::new(input))
        .with_guessed_format()
        .map_err(|_| CryptoError::UnsupportedMedia)?;
    let format = reader.format().ok_or(CryptoError::UnsupportedMedia)?;
    let output_format = match format {
        ImageFormat::Jpeg => ImageFormat::Jpeg,
        ImageFormat::Png => ImageFormat::Png,
        _ => return Err(CryptoError::UnsupportedMedia),
    };
    let decoded = reader.decode().map_err(|_| CryptoError::UnsupportedMedia)?;
    let mut output = Cursor::new(Vec::new());
    decoded.write_to(&mut output, output_format)?;
    Ok(output.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};

    #[test]
    fn sanitizes_supported_raster_images_and_rejects_unknown_formats() {
        let image = DynamicImage::ImageRgb8(ImageBuffer::from_pixel(1, 1, Rgb([1, 2, 3])));
        let mut encoded = Cursor::new(Vec::new());
        image.write_to(&mut encoded, ImageFormat::Png).unwrap();

        let sanitized = strip_image_metadata(encoded.get_ref()).unwrap();
        assert!(matches!(
            ImageReader::new(Cursor::new(&sanitized))
                .with_guessed_format()
                .unwrap()
                .format(),
            Some(ImageFormat::Png)
        ));
        assert!(matches!(
            strip_image_metadata(b"not an image"),
            Err(CryptoError::UnsupportedMedia)
        ));
    }

    #[test]
    fn removes_jpeg_exif_by_reencoding_pixels() {
        let image = DynamicImage::ImageRgb8(ImageBuffer::from_pixel(1, 1, Rgb([1, 2, 3])));
        let mut encoded = Cursor::new(Vec::new());
        image.write_to(&mut encoded, ImageFormat::Jpeg).unwrap();
        let jpeg = encoded.into_inner();

        let mut tagged = jpeg[..2].to_vec();
        tagged.extend_from_slice(&[
            0xff, 0xe1, 0x00, 0x10, b'E', b'x', b'i', b'f', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        tagged.extend_from_slice(&jpeg[2..]);

        let sanitized = strip_image_metadata(&tagged).unwrap();
        assert!(!sanitized.windows(4).any(|window| window == b"Exif"));
    }
}
