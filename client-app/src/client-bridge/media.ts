export class UnsupportedAttachmentError extends Error {
  constructor() {
    super("Поддерживаются только JPEG и PNG. Аудио, документы и другие форматы прикрепить нельзя.");
    this.name = "UnsupportedAttachmentError";
  }
}

export interface SanitizedImage {
  file: File;
  previewUrl: string;
  mimeType: "image/jpeg" | "image/png";
}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

export async function sanitizeImageForDemo(file: File): Promise<SanitizedImage> {
  const isJpeg = file.type === "image/jpeg";
  const isPng = file.type === "image/png";
  if (!isJpeg && !isPng) throw new UnsupportedAttachmentError();

  const header = new Uint8Array(await file.slice(0, 8).arrayBuffer());
  const hasJpegSignature =
    header.length >= 3 && header[0] === 0xff && header[1] === 0xd8 && header[2] === 0xff;
  const hasPngSignature =
    header.length === PNG_SIGNATURE.length &&
    PNG_SIGNATURE.every((byte, index) => header[index] === byte);
  if ((isJpeg && !hasJpegSignature) || (isPng && !hasPngSignature)) {
    throw new UnsupportedAttachmentError();
  }

  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new UnsupportedAttachmentError();
  }

  try {
    const canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const context = canvas.getContext("2d", { alpha: isPng });
    if (!context) throw new Error("Не удалось подготовить безопасное изображение.");
    context.drawImage(bitmap, 0, 0);

    const cleanBlob = await new Promise<Blob>((resolve, reject) => {
      canvas.toBlob(
        (blob) => {
          if (blob) resolve(blob);
          else reject(new Error("Не удалось повторно закодировать изображение."));
        },
        file.type,
        isJpeg ? 0.94 : undefined,
      );
    });
    const cleanFile = new File([cleanBlob], file.name, {
      type: file.type,
      lastModified: Date.now(),
    });
    return {
      file: cleanFile,
      previewUrl: URL.createObjectURL(cleanBlob),
      mimeType: file.type,
    };
  } finally {
    bitmap.close();
  }
}
