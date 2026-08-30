import crypto from 'crypto';
import { verifyWebhookSignature } from '../src/webhook';

describe('Webhook Signature Verification', () => {
  const secret = 'test-chapa-webhook-secret';
  const payloadStr = JSON.stringify({
    event: 'charge.complete',
    tx_ref: 'TX-123456',
    amount: '100.00',
    currency: 'ETB',
    status: 'success',
  });

  const validSignature = crypto
    .createHmac('sha256', secret)
    .update(Buffer.from(payloadStr, 'utf8'))
    .digest('hex');

  it('should verify a valid signature with string payload', () => {
    const isValid = verifyWebhookSignature(payloadStr, validSignature, secret);
    expect(isValid).toBe(true);
  });

  it('should verify a valid signature with Buffer payload', () => {
    const bufferPayload = Buffer.from(payloadStr, 'utf8');
    const isValid = verifyWebhookSignature(
      bufferPayload,
      validSignature,
      secret
    );
    expect(isValid).toBe(true);
  });

  it('should reject a tampered payload', () => {
    const tampered = payloadStr.replace('100.00', '999.00');
    const isValid = verifyWebhookSignature(tampered, validSignature, secret);
    expect(isValid).toBe(false);
  });

  it('should reject an incorrect signature', () => {
    const wrongSignature = 'a'.repeat(64);
    const isValid = verifyWebhookSignature(payloadStr, wrongSignature, secret);
    expect(isValid).toBe(false);
  });

  it('should reject a wrong-length signature without throwing RangeError', () => {
    expect(() =>
      verifyWebhookSignature(payloadStr, 'short-sig', secret)
    ).not.toThrow();
    expect(verifyWebhookSignature(payloadStr, 'short-sig', secret)).toBe(false);
    expect(verifyWebhookSignature(payloadStr, 'a'.repeat(63), secret)).toBe(
      false
    );
    expect(verifyWebhookSignature(payloadStr, 'a'.repeat(65), secret)).toBe(
      false
    );
  });

  it('should reject malformed non-hex signatures safely', () => {
    const nonHex = 'z'.repeat(64);
    expect(verifyWebhookSignature(payloadStr, nonHex, secret)).toBe(false);
  });

  it('should return false for empty or missing arguments', () => {
    expect(verifyWebhookSignature('', validSignature, secret)).toBe(false);
    expect(verifyWebhookSignature(payloadStr, '', secret)).toBe(false);
    expect(verifyWebhookSignature(payloadStr, validSignature, '')).toBe(false);
    expect(verifyWebhookSignature(null as any, validSignature, secret)).toBe(
      false
    );
  });

  it('should handle unicode characters correctly in payload', () => {
    const unicodePayload = JSON.stringify({
      name: 'አበበ ቢቂላ',
      amount: 100,
    });
    const unicodeSig = crypto
      .createHmac('sha256', secret)
      .update(Buffer.from(unicodePayload, 'utf8'))
      .digest('hex');

    expect(verifyWebhookSignature(unicodePayload, unicodeSig, secret)).toBe(
      true
    );
  });
});
