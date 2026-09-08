// NOSTR, the minimum a chat connector needs (PLAN §1, I5).
//
// Hand-written rather than a library, for the same reason the ACP bridge writes its own RFC 6455:
// the surface we use is small and completely specified, and this package is installed by every
// self-hoster — a dependency here is a dependency for all of them. What is NOT hand-written is the
// cryptography: `@noble/curves` does the BIP-340 Schnorr signing Nostr is built on (audited, and
// the same family the cloud already uses to mint an agent's keypair), and `@scure/base` the bech32.
//
// Covered: NIP-01 (event id, signature, the wire messages), NIP-42 (authenticating to a relay as
// the agent), and the tags a group message needs. NOT covered: NIP-44/59 gift wraps, so direct
// messages are out of scope for now — a channel is what "add an agent like a person" means, and a
// DM needs a second, larger piece of cryptography (BACKLOG).
import { schnorr } from "@noble/curves/secp256k1.js";
import { bech32 } from "@scure/base";

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export type UnsignedEvent = Omit<NostrEvent, "id" | "pubkey" | "sig">;

const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s: string): Uint8Array => new Uint8Array((s.match(/.{1,2}/g) ?? []).map((b) => parseInt(b, 16)));

/** A bech32 `nsec1…` (or a raw 64-char hex key) as bytes. Anything else is not a key. */
export function secretKeyBytes(nsec: string): Uint8Array {
  const s = nsec.trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return unhex(s);
  const d = bech32.decode(s as `${string}1${string}`, 200);
  if (d.prefix !== "nsec") throw new Error(`expected an nsec, got ${d.prefix}`);
  return new Uint8Array(bech32.fromWords(d.words));
}

/** The x-only public key (NIP-01's `pubkey`), as hex. */
export const publicKeyHex = (sk: Uint8Array): string => hex(schnorr.getPublicKey(sk));

/** `npub1…` for a hex pubkey — what a person pastes into a chat app to add the agent. */
export const npubOf = (pubkeyHex: string): string => bech32.encode("npub", bech32.toWords(unhex(pubkeyHex)));

/** The hex pubkey inside an `npub1…`. */
export function pubkeyOfNpub(npub: string): string {
  const d = bech32.decode(npub.trim() as `${string}1${string}`, 200);
  if (d.prefix !== "npub") throw new Error(`expected an npub, got ${d.prefix}`);
  return hex(new Uint8Array(bech32.fromWords(d.words)));
}

// NIP-01: the id is the SHA-256 of a canonical, whitespace-free JSON array. The order is fixed by
// the spec — this is a serialization, not an object, and re-ordering it changes the id.
async function eventId(pubkey: string, e: UnsignedEvent): Promise<string> {
  const serial = JSON.stringify([0, pubkey, e.created_at, e.kind, e.tags, e.content]);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(serial));
  return hex(new Uint8Array(digest));
}

/** Sign an event as the holder of `sk`. */
export async function signEvent(sk: Uint8Array, e: UnsignedEvent): Promise<NostrEvent> {
  const pubkey = publicKeyHex(sk);
  const id = await eventId(pubkey, e);
  const sig = hex(await schnorr.sign(unhex(id), sk));
  return { ...e, id, pubkey, sig };
}

/** Verify one — used on everything a relay sends, because a relay is not a trusted narrator. */
export async function verifyEvent(e: NostrEvent): Promise<boolean> {
  try {
    if ((await eventId(e.pubkey, e)) !== e.id) return false;
    return await schnorr.verify(unhex(e.sig), unhex(e.id), unhex(e.pubkey));
  } catch {
    return false;
  }
}

export const now = (): number => Math.floor(Date.now() / 1000);

/** The first value of a tag, e.g. `tagValue(e, "h")` for the channel a message belongs to. */
export const tagValue = (e: NostrEvent, name: string): string | undefined => e.tags.find((t) => t[0] === name)?.[1];

/** Every value of a repeated tag — `p` for mentions, `e` for thread references. */
export const tagValues = (e: NostrEvent, name: string): string[] => e.tags.filter((t) => t[0] === name).map((t) => t[1]).filter(Boolean);

/** NIP-10: the root of the thread a reply belongs to, if it is one. */
export function threadRoot(e: NostrEvent): string | undefined {
  const es = e.tags.filter((t) => t[0] === "e");
  return es.find((t) => t[3] === "root")?.[1] ?? es.find((t) => t[3] === "reply")?.[1] ?? es[0]?.[1];
}

// ── NIP-42 ─────────────────────────────────────────────────────────────────────────────────────
// A relay may challenge a connection; the answer is a kind 22242 event naming the relay and the
// challenge, signed by the key we claim to be. It is never stored, and never sent unprompted.
export const AUTH_KIND = 22242;

export const authEvent = (sk: Uint8Array, relay: string, challenge: string): Promise<NostrEvent> =>
  signEvent(sk, { created_at: now(), kind: AUTH_KIND, tags: [["relay", relay], ["challenge", challenge]], content: "" });

// ── Buzz's own kinds ───────────────────────────────────────────────────────────────────────────
// From github.com/block/buzz (ARCHITECTURE.md, NOSTR.md, read 2026-09-08): a channel message is
// kind 9 carrying `#h <channel-uuid>`; 40002 is the same thing in Buzz's richer format; mentions
// are `p` tags. Kind 0 is the standard profile, which is how an agent gets a name people see.
export const KIND_MESSAGE = 9;
export const KIND_MESSAGE_RICH = 40002;
export const KIND_PROFILE = 0;
export const MESSAGE_KINDS = [KIND_MESSAGE, KIND_MESSAGE_RICH];

/** A message in a Buzz channel, optionally replying in a thread and mentioning people. */
export function channelMessage(channel: string, text: string, o: { replyTo?: string; root?: string; mentions?: string[] } = {}): UnsignedEvent {
  const tags: string[][] = [["h", channel]];
  // NIP-10 marked form: the root first, then the message being replied to. Buzz creates its thread
  // metadata from exactly this, so an unmarked `e` tag would land the reply outside the thread.
  if (o.root) tags.push(["e", o.root, "", "root"]);
  if (o.replyTo && o.replyTo !== o.root) tags.push(["e", o.replyTo, "", "reply"]);
  for (const p of o.mentions ?? []) tags.push(["p", p]);
  return { created_at: now(), kind: KIND_MESSAGE, tags, content: text };
}

/** The agent's profile — its name in the room, published once so it is not a bare key. */
export const profileEvent = (name: string, about?: string): UnsignedEvent => ({
  created_at: now(),
  kind: KIND_PROFILE,
  tags: [],
  content: JSON.stringify({ name, ...(about ? { about } : {}), bot: true }),
});
