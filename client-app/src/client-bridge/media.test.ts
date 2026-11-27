import { describe, expect, it } from "vitest";
import { sanitizeImageForDemo, UnsupportedAttachmentError } from "./media";

describe("sanitizeImageForDemo", () => {
  it("rejects audio and document files with a clear unsupported-media error", async () => {
    const audio = new File(["audio"], "voice.ogg", { type: "audio/ogg" });
    await expect(sanitizeImageForDemo(audio)).rejects.toBeInstanceOf(
      UnsupportedAttachmentError,
    );
  });

  it("rejects image MIME types that do not match JPEG or PNG signatures", async () => {
    const mislabeledImage = new File(["not an image"], "photo.jpg", {
      type: "image/jpeg",
    });
    await expect(sanitizeImageForDemo(mislabeledImage)).rejects.toBeInstanceOf(
      UnsupportedAttachmentError,
    );
  });
});
