import type { WebhookPayload, VerifyResult } from "./types.js";
/**
 * Build a webhook event payload from a VerifyResult.
 * BigInt fields are serialized to strings for JSON compatibility.
 */
export declare function buildEvent(result: VerifyResult, event: "payment.confirmed" | "payment.overpaid"): WebhookPayload;
/**
 * Sign a webhook payload with HMAC-SHA256.
 * Returns the hex signature string (to be sent as the `X-BaseReceipt-Signature` header).
 *
 * @param payload - The WebhookPayload object.
 * @param secret  - The webhook secret (from env: WEBHOOK_SECRET). Never log this.
 */
export declare function signWebhook(payload: WebhookPayload, secret: string): string;
/**
 * Verify an incoming webhook signature.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * @param body      - Raw request body string (do NOT parse before verifying).
 * @param signature - The `X-BaseReceipt-Signature` header value.
 * @param secret    - Your webhook secret.
 */
export declare function verifyWebhook(body: string, signature: string, secret: string): boolean;
/**
 * Dispatch a signed webhook to a URL.
 * Throws if the endpoint returns a non-2xx status.
 */
export declare function sendWebhook(url: string, payload: WebhookPayload, secret: string): Promise<void>;
//# sourceMappingURL=webhook.d.ts.map