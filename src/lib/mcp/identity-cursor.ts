import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { idSchema, timestampSchema } from "../agents/contracts";

export const positionSchema = z.strictObject({ time: timestampSchema, id: idSchema });
export type EventPosition = z.infer<typeof positionSchema>;
const payloadSchema = z.strictObject({
  version: z.literal(1), binding: z.string().length(64), asOf: timestampSchema,
  position: positionSchema, expiresAt: z.number().int().positive()
});
export class InvalidCursorError extends Error {}

/** Server-only codec: encrypted, tamper-evident and bound to a normalized run/query. */
export function createIdentityCursorCodec(key: Uint8Array) {
  if (key.byteLength !== 32) throw new Error("Cursor key must contain 32 bytes");
  const secret = Buffer.from(key);
  const aad = Buffer.from("trustmesh.identity.cursor.v1");
  const binding = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
  return {
    encode(query: unknown, asOf: string, position: EventPosition, expiresAt: number): string {
      const payload = payloadSchema.parse({ version: 1, binding: binding(query), asOf, position, expiresAt });
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", secret, iv);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64url");
    },
    decode(value: string, query: unknown, now: number) {
      try {
        if (value.length > 2048 || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error();
        const bytes = Buffer.from(value, "base64url");
        if (bytes.length < 29 || bytes.toString("base64url") !== value) throw new Error();
        const decipher = createDecipheriv("aes-256-gcm", secret, bytes.subarray(0, 12));
        decipher.setAAD(aad); decipher.setAuthTag(bytes.subarray(12, 28));
        const payload = payloadSchema.parse(JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8")));
        if (payload.binding !== binding(query) || payload.expiresAt <= now || Date.parse(payload.asOf) > now) throw new Error();
        return payload;
      } catch { throw new InvalidCursorError("Invalid, expired or out-of-scope cursor"); }
    }
  };
}
export type IdentityCursorCodec = ReturnType<typeof createIdentityCursorCodec>;
