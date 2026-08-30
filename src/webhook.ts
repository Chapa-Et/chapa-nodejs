import crypto from 'crypto';

/**
 * Verifies Chapa webhook signatures using HMAC-SHA256 with constant-time comparison.
 *
 * @param payload - The raw request payload (string or Buffer).
 * @param signature - The signature received in the `x-chapa-signature` or `chapa-signature` header.
 * @param secret - The Chapa secret key or webhook secret.
 * @returns boolean indicating whether the signature is valid.
 */
export function verifyWebhookSignature(
  payload: string | Buffer,
  signature: string,
  secret: string
): boolean {
  if (!payload || !signature || !secret) {
    return false;
  }

  try {
    const rawBody = Buffer.isBuffer(payload)
      ? payload
      : Buffer.from(payload, 'utf8');

    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(rawBody)
      .digest('hex');

    const expectedBuf = Buffer.from(expectedSignature, 'hex');
    const cleanSignature = signature.trim();
    const receivedBuf = Buffer.from(cleanSignature, 'hex');

    // Both SHA256 hex digests must be exactly 32 bytes (64 hex characters)
    if (
      expectedBuf.length !== 32 ||
      receivedBuf.length !== 32 ||
      cleanSignature.length !== 64
    ) {
      return false;
    }

    return crypto.timingSafeEqual(expectedBuf, receivedBuf);
  } catch {
    return false;
  }
}
