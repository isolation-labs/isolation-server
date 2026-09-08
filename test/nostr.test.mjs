// The Nostr primitives (src/nostr.ts) — the part of the Buzz connector that is pure and is where a
// mistake is silent. A wrong event id or a wrong tag order does not throw: the relay simply
// rejects the message, or worse accepts it into the wrong thread.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.ISOLATION_SERVER_HOME = mkdtempSync(join(tmpdir(), "iso-nostr-"));
process.on("exit", () => rmSync(process.env.ISOLATION_SERVER_HOME, { recursive: true, force: true }));

const n = await import("../dist/nostr.js");

// A key we can assert against: the BIP-340 test vector's private key, so the pubkey derivation is
// checked against something outside our own code.
const SK_HEX = "0000000000000000000000000000000000000000000000000000000000000003";
const PK_HEX = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

test("keys: hex and nsec both parse, the pubkey is x-only, and npub round-trips", async () => {
  const sk = n.secretKeyBytes(SK_HEX);
  assert.equal(n.publicKeyHex(sk), PK_HEX, "the x-only pubkey matches the BIP-340 vector");

  const npub = n.npubOf(PK_HEX);
  assert.match(npub, /^npub1/);
  assert.equal(n.pubkeyOfNpub(npub), PK_HEX, "and back again");

  // An nsec is the same key in bech32 — parsing either must give the same bytes.
  const { bech32 } = await import("@scure/base");
  const nsec = bech32.encode("nsec", bech32.toWords(sk));
  assert.deepEqual([...n.secretKeyBytes(nsec)], [...sk]);

  assert.throws(() => n.secretKeyBytes(npub), /expected an nsec/, "an npub is not a secret key");
  assert.throws(() => n.pubkeyOfNpub(nsec), /expected an npub/);
});

test("an event is signed over its canonical id, and any change to it fails verification", async () => {
  const sk = n.secretKeyBytes(SK_HEX);
  const ev = await n.signEvent(sk, n.channelMessage("chan-uuid", "hello"));

  assert.equal(ev.pubkey, PK_HEX);
  assert.match(ev.id, /^[0-9a-f]{64}$/);
  assert.match(ev.sig, /^[0-9a-f]{128}$/);
  assert.equal(await n.verifyEvent(ev), true);

  // The id is a commitment to every field, so tampering is caught even with the signature intact.
  assert.equal(await n.verifyEvent({ ...ev, content: "goodbye" }), false, "content");
  assert.equal(await n.verifyEvent({ ...ev, created_at: ev.created_at + 1 }), false, "timestamp");
  assert.equal(await n.verifyEvent({ ...ev, tags: [...ev.tags, ["h", "another-channel"]] }), false, "tags");
  assert.equal(await n.verifyEvent({ ...ev, sig: ev.sig.replace(/.$/, (c) => (c === "0" ? "1" : "0")) }), false, "signature");
  assert.equal(await n.verifyEvent({ ...ev, id: ev.id.replace(/.$/, (c) => (c === "0" ? "1" : "0")) }), false, "id");
});

test("a channel message carries the channel, its thread markers and its mentions, in NIP-10 order", () => {
  const plain = n.channelMessage("C1", "hi");
  assert.deepEqual(plain.tags, [["h", "C1"]], "a channel message is nothing without its #h tag");
  assert.equal(plain.kind, 9);

  const reply = n.channelMessage("C1", "answering", { root: "ROOT", replyTo: "PARENT", mentions: ["PK1", "PK2"] });
  assert.deepEqual(reply.tags, [
    ["h", "C1"],
    ["e", "ROOT", "", "root"],
    ["e", "PARENT", "", "reply"],
    ["p", "PK1"],
    ["p", "PK2"],
  ]);

  // Replying to the root itself must not repeat it — Buzz builds thread metadata from these.
  const atRoot = n.channelMessage("C1", "x", { root: "ROOT", replyTo: "ROOT" });
  assert.deepEqual(atRoot.tags, [["h", "C1"], ["e", "ROOT", "", "root"]]);
});

test("reading tags back: the channel, the mentions, and which thread a message belongs to", () => {
  const ev = {
    id: "x", pubkey: "p", created_at: 0, kind: 9, sig: "s", content: "",
    tags: [["h", "C1"], ["e", "ROOT", "", "root"], ["e", "PARENT", "", "reply"], ["p", "A"], ["p", "B"]],
  };
  assert.equal(n.tagValue(ev, "h"), "C1");
  assert.deepEqual(n.tagValues(ev, "p"), ["A", "B"]);
  assert.equal(n.threadRoot(ev), "ROOT", "a marked root wins");

  assert.equal(n.threadRoot({ ...ev, tags: [["e", "PARENT", "", "reply"]] }), "PARENT", "…else the reply marker");
  assert.equal(n.threadRoot({ ...ev, tags: [["e", "SOMETHING"]] }), "SOMETHING", "…else the first e tag (unmarked, legacy)");
  assert.equal(n.threadRoot({ ...ev, tags: [["h", "C1"]] }), undefined, "a top-level message is in no thread");
});

test("the NIP-42 answer names the relay and the challenge, and is signed by the agent", async () => {
  const sk = n.secretKeyBytes(SK_HEX);
  const ev = await n.authEvent(sk, "wss://relay.example", "chal-123");
  assert.equal(ev.kind, 22242);
  assert.equal(n.tagValue(ev, "relay"), "wss://relay.example");
  assert.equal(n.tagValue(ev, "challenge"), "chal-123");
  assert.equal(ev.pubkey, PK_HEX, "the relay learns which key answered");
  assert.equal(await n.verifyEvent(ev), true);
});

test("a profile says the name people see, and that it is a bot", async () => {
  const ev = await n.signEvent(n.secretKeyBytes(SK_HEX), n.profileEvent("Isla", "An Isolation agent."));
  assert.equal(ev.kind, 0);
  const p = JSON.parse(ev.content);
  assert.equal(p.name, "Isla");
  assert.equal(p.bot, true, "a person should be able to tell");
});
