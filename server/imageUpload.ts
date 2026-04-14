/**
 * Image upload handler for webcam captures during intrusion events
 */

import { storagePut } from "./storage";
import { updateIntrusionLog } from "./db";
import { nanoid } from "nanoid";

export async function uploadIntrusionImage(
  imageBuffer: Buffer,
  intrusionId?: number
): Promise<{ url: string; key: string } | null> {
  try {
    // Generate unique key for the image
    const imageKey = `intrusions/${nanoid()}-${Date.now()}.jpg`;

    // Upload to S3
    const { url } = await storagePut(imageKey, imageBuffer, "image/jpeg");

    // If we have an intrusion ID, update the record with the image URL
    if (intrusionId) {
      await updateIntrusionLog(intrusionId, {
        imageUrl: url,
        imageKey: imageKey,
      });
    }

    return { url, key: imageKey };
  } catch (error) {
    console.error("[ImageUpload] Error uploading intrusion image:", error);
    return null;
  }
}
