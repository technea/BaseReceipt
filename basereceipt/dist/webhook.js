import { createHmac, timingSafeEqual } from "node:crypto";
/**
 * Build a webhook event payload from a VerifyResult.
 * BigInt fields are serialized to strings for JSON compatibility.
 */
export function buildEvent(result, event) {
    return {
        event,
        invoiceId: result.invoiceId,
        result: {
            status: result.status,
            invoiceId: result.invoiceId,
            txHash: result.txHash,
            paidAtomic: result.paidAtomic.toString(),
            requiredAtomic: result.requiredAtomic.toString(),
            blockNumber: result.blockNumber.toString(),
            verifiedAt: result.verifiedAt,
            tokenAddress: result.tokenAddress,
            recipient: result.recipient,
            from: result.from,
            network: result.network,
        },
        timestamp: new Date().toISOString(),
    };
}
/**
 * Sign a webhook payload with HMAC-SHA256.
 * Returns the hex signature string (to be sent as the `X-BaseReceipt-Signature` header).
 *
 * @param payload - The WebhookPayload object.
 * @param secret  - The webhook secret (from env: WEBHOOK_SECRET). Never log this.
 */
export function signWebhook(payload, secret) {
    const body = JSON.stringify(payload);
    return createHmac("sha256", secret).update(body).digest("hex");
}
/**
 * Verify an incoming webhook signature.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * @param body      - Raw request body string (do NOT parse before verifying).
 * @param signature - The `X-BaseReceipt-Signature` header value.
 * @param secret    - Your webhook secret.
 */
export function verifyWebhook(body, signature, secret) {
    try {
        const expected = createHmac("sha256", secret).update(body).digest("hex");
        const expectedBuf = Buffer.from(expected, "hex");
        const actualBuf = Buffer.from(signature, "hex");
        if (expectedBuf.length !== actualBuf.length)
            return false;
        return timingSafeEqual(expectedBuf, actualBuf);
    }
    catch {
        return false;
    }
}
/**
 * Dispatch a signed webhook to a URL.
 * Throws if the endpoint returns a non-2xx status.
 */
export async function sendWebhook(url, payload, secret) {
    const body = JSON.stringify(payload);
    const signature = signWebhook(payload, secret);
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            "x-basereceipt-signature": signature,
            "x-basereceipt-event": payload.event,
        },
        body,
    });
    if (!response.ok) {
        throw new Error(`Webhook delivery failed: ${response.status} ${response.statusText} → ${url}`);
    }
}
//# sourceMappingURL=webhook.js.map