// WebDAV: the pure pieces (paths, PROPFIND parsing, ranges, destinations) plus the one impure
// piece that no type checker can vouch for — the streamed multipart upload, exercised against a
// real HTTP server so the framing and the Content-Length/chunked question are answered by undici
// rather than by hope.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";

const { davRelPath, parsePropfind, parseRange, destinationRel, ifTokens } = await import("../dist/webdav.js");
const { uploadBody, UploadTooLarge, writeFileStream } = await import("../dist/execd.js");
const { basicToken } = await import("../dist/doorman.js");

// ── paths ────────────────────────────────────────────────────────────────────────────────────────

test("davRelPath decodes, and refuses anything that could leave the root", () => {
  assert.equal(davRelPath(""), "");
  assert.equal(davRelPath("/"), "");
  assert.equal(davRelPath("/a/b.txt"), "a/b.txt");
  assert.equal(davRelPath("/a/"), "a");
  assert.equal(davRelPath("/My%20Docs/re%CC%81sume%CC%81.txt"), "My Docs/résumé.txt");
  // A name with a `#`, a `?` or a `+` survives intact — they are ordinary filename characters and a
  // files view that mangles them is broken.
  assert.equal(davRelPath("/a%23b/c%3Fd/e%2Bf"), "a#b/c?d/e+f");
  // Escapes
  assert.equal(davRelPath("/../etc/passwd"), undefined);
  assert.equal(davRelPath("/a/../../b"), undefined);
  assert.equal(davRelPath("/a/./b"), undefined);
  assert.equal(davRelPath("/a//b"), undefined);
  assert.equal(davRelPath("/%2e%2e/x"), undefined, "an ENCODED .. must not slip through");
  // The traversal that survives splitting on `/`: one segment that only BECOMES `../..` once it is
  // decoded, so it is never compared against "..".
  assert.equal(davRelPath("/..%2f..%2fetc/passwd"), undefined);
  assert.equal(davRelPath("/%2e%2e%2f%2e%2e%2fetc"), undefined);
  assert.equal(davRelPath("/a%2Fb"), undefined, "no filename contains a slash");
  assert.equal(davRelPath("/a/%00b"), undefined, "a NUL byte would truncate the path in the shell");
  assert.equal(davRelPath("/a/b%0Ac"), undefined, "a newline would forge a line in the stat output");
  assert.equal(davRelPath("/a/%ff%fe"), undefined, "a malformed escape is not a name");
  assert.equal(davRelPath(`/${"x".repeat(3000)}`), undefined);
  // Backslashes and spaces ARE legal on a real filesystem and must survive.
  assert.equal(davRelPath("/a%5Cb"), "a\\b");
});

// ── PROPFIND ─────────────────────────────────────────────────────────────────────────────────────

test("parsePropfind: an empty body is allprop", () => {
  assert.deepEqual(parsePropfind(""), { mode: "allprop", props: [] });
  assert.deepEqual(parsePropfind("   \n "), { mode: "allprop", props: [] });
});

test("parsePropfind reads an explicit prop list and keeps foreign namespaces", () => {
  // The shape macOS actually sends: a DAV: prefix plus Apple's own namespace.
  const body = `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:A="http://apple.com/ns/">
  <D:prop><D:resourcetype/><D:getcontentlength/><A:appledoubleheader/></D:prop>
</D:propfind>`;
  const out = parsePropfind(body);
  assert.equal(out.mode, "prop");
  assert.deepEqual(out.props, [
    { ns: "DAV:", name: "resourcetype" },
    { ns: "DAV:", name: "getcontentlength" },
    { ns: "http://apple.com/ns/", name: "appledoubleheader" },
  ]);
});

test("parsePropfind handles a default namespace and <propname/>", () => {
  const dflt = `<propfind xmlns="DAV:"><prop><displayname/><getetag/></prop></propfind>`;
  assert.deepEqual(parsePropfind(dflt).props, [
    { ns: "DAV:", name: "displayname" },
    { ns: "DAV:", name: "getetag" },
  ]);
  assert.equal(parsePropfind(`<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>`).mode, "propname");
  assert.equal(parsePropfind(`<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>`).mode, "allprop");
});

test("parsePropfind ignores comments and duplicate props", () => {
  const body = `<d:propfind xmlns:d="DAV:"><!-- <d:allprop/> --><d:prop><d:getetag/><d:getetag/></d:prop></d:propfind>`;
  const out = parsePropfind(body);
  assert.equal(out.mode, "prop");
  assert.deepEqual(out.props, [{ ns: "DAV:", name: "getetag" }]);
});

// ── Range ────────────────────────────────────────────────────────────────────────────────────────

test("parseRange covers the forms a file client sends", () => {
  assert.deepEqual(parseRange("bytes=0-99", 1000), { start: 0, end: 99 });
  assert.deepEqual(parseRange("bytes=500-", 1000), { start: 500, end: 999 });
  assert.deepEqual(parseRange("bytes=-100", 1000), { start: 900, end: 999 }, "a suffix range is the LAST n bytes");
  assert.deepEqual(parseRange("bytes=0-99999", 1000), { start: 0, end: 999 }, "an over-long end clamps to the file");
  assert.equal(parseRange(undefined, 1000), undefined);
  assert.equal(parseRange("bytes=0-0,10-20", 1000), undefined, "multi-range falls back to the whole file");
  assert.equal(parseRange("bytes=1000-1100", 1000), "unsatisfiable");
  assert.equal(parseRange("bytes=50-10", 1000), "unsatisfiable");
  assert.equal(parseRange("bytes=0-10", 0), "unsatisfiable");
});

// ── MOVE / COPY destinations ─────────────────────────────────────────────────────────────────────

test("destinationRel accepts this mount only, whatever host the client mounted", () => {
  const prefix = "/v/v-abc123/dav";
  // The host is NOT checked — through the tunnel it is a name this process never learns — but the
  // path must lie inside the mount.
  assert.equal(destinationRel("https://v--srv.isolation.cc/v/v-abc123/dav/a/b.txt", prefix), "a/b.txt");
  assert.equal(destinationRel("/v/v-abc123/dav/a%20b.txt", prefix), "a b.txt");
  assert.equal(destinationRel("https://x/v/v-OTHER/dav/a", prefix), undefined, "another view is not this mount");
  assert.equal(destinationRel("https://x/etc/passwd", prefix), undefined);
  assert.equal(destinationRel("/v/v-abc123/dav/../../etc", prefix), undefined);
  assert.equal(destinationRel(undefined, prefix), undefined);
  // A sibling whose path merely STARTS with the prefix string is not inside it.
  assert.equal(destinationRel("/v/v-abc123/davILY/x", prefix), undefined);
});

test("ifTokens pulls lock tokens out of an If header", () => {
  assert.deepEqual(ifTokens("(<opaquelocktoken:abc-123>)"), ["opaquelocktoken:abc-123"]);
  assert.deepEqual(ifTokens("</a/b.txt> (<opaquelocktoken:x> [\"etag\"])"), ["opaquelocktoken:x"]);
  assert.deepEqual(ifTokens(undefined), []);
  assert.deepEqual(ifTokens("(Not <opaquelocktoken:a>) (<urn:uuid:b>)"), ["opaquelocktoken:a", "urn:uuid:b"]);
});

// ── the mount credential ─────────────────────────────────────────────────────────────────────────

test("basicToken reads the password, and falls back to the username", () => {
  const b64 = (s) => Buffer.from(s, "utf8").toString("base64");
  assert.equal(basicToken(`Basic ${b64("isolation:s3cret")}`), "s3cret");
  assert.equal(basicToken(`basic ${b64("isolation:s3cret")}`), "s3cret", "the scheme is case-insensitive");
  // A password holding a colon is kept whole: only the FIRST colon separates the two fields.
  assert.equal(basicToken(`Basic ${b64("u:a:b:c")}`), "a:b:c");
  assert.equal(basicToken(`Basic ${b64("tokenonly")}`), "tokenonly");
  assert.equal(basicToken(`Basic ${b64("tokenonly:")}`), "tokenonly", "an empty password falls back to the username");
  assert.equal(basicToken("Bearer abc"), undefined);
  assert.equal(basicToken(undefined), undefined);
});

// ── the streamed upload, against a real server ───────────────────────────────────────────────────

// Collect a multipart body the way execd's Go parser would: split on the boundary and hand back
// each part's headers and bytes.
function parseMultipart(buf, boundary) {
  const sep = Buffer.from(`--${boundary}`);
  const parts = [];
  let i = buf.indexOf(sep);
  while (i !== -1) {
    const start = i + sep.length;
    if (buf.slice(start, start + 2).toString() === "--") break; // closing boundary
    const bodyStart = buf.indexOf("\r\n\r\n", start) + 4;
    const next = buf.indexOf(sep, bodyStart);
    if (next === -1) break;
    parts.push({
      headers: buf.slice(start + 2, bodyStart - 4).toString("utf8"),
      body: buf.slice(bodyStart, next - 2), // minus the CRLF before the boundary
    });
    i = next;
  }
  return parts;
}

async function withUploadServer(run) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  try {
    return await run(`http://127.0.0.1:${port}`, seen);
  } finally {
    server.close();
  }
}

const asStream = async function* (...chunks) {
  for (const c of chunks) yield Buffer.from(c);
};

test("uploadBody frames execd's two parts and streams the body through undici", async () => {
  const payload = Buffer.alloc(3 * 1024 * 1024, 0x41); // 3MB, well past one chunk
  await withUploadServer(async (origin, seen) => {
    const { stream, headers } = uploadBody("/workspace/big.bin", asStream(payload.subarray(0, 1 << 20), payload.subarray(1 << 20)), {
      mode: 0o644,
      contentLength: payload.length,
    });
    const r = await fetch(`${origin}/files/upload`, { method: "POST", headers, body: stream, duplex: "half" });
    assert.equal(r.status, 200);

    const got = seen[0];
    const boundary = /boundary=(\S+)/.exec(got.headers["content-type"])[1];
    // A known length must travel as Content-Length, NOT chunked: that is the shape execd's parser
    // has always been fed, and the reason the length is threaded through at all.
    assert.equal(got.headers["content-length"], String(got.body.length));
    assert.equal(got.headers["transfer-encoding"], undefined);

    const parts = parseMultipart(got.body, boundary);
    assert.equal(parts.length, 2);
    // execd's quirks, both of them: metadata is a FILE part, and `mode` is a JSON number whose
    // DECIMAL digits are read as octal — 0o644 must arrive as 644, not 420.
    assert.match(parts[0].headers, /name="metadata"; filename="metadata\.json"/);
    assert.deepEqual(JSON.parse(parts[0].body.toString("utf8")), { path: "/workspace/big.bin", mode: 644 });
    assert.match(parts[1].headers, /name="file"/);
    assert.equal(parts[1].body.length, payload.length);
    assert.ok(parts[1].body.equals(payload), "the bytes arrive unaltered");
  });
});

test("uploadBody streams an unknown-length body as chunked", async () => {
  await withUploadServer(async (origin, seen) => {
    const { stream, headers } = uploadBody("/workspace/a.txt", asStream("hello ", "world"), { mode: 0o644 });
    await fetch(`${origin}/files/upload`, { method: "POST", headers, body: stream, duplex: "half" });
    const got = seen[0];
    assert.equal(got.headers["content-length"], undefined);
    assert.equal(got.headers["transfer-encoding"], "chunked");
    const boundary = /boundary=(\S+)/.exec(got.headers["content-type"])[1];
    assert.equal(parseMultipart(got.body, boundary)[1].body.toString(), "hello world");
  });
});

test("a body that runs past maxBytes aborts instead of writing a truncated file", async () => {
  await withUploadServer(async (origin, seen) => {
    const { stream, headers } = uploadBody("/workspace/huge.bin", asStream(Buffer.alloc(1024), Buffer.alloc(1024)), { maxBytes: 1500 });
    await assert.rejects(
      fetch(`${origin}/files/upload`, { method: "POST", headers, body: stream, duplex: "half" }),
      // undici wraps the stream's throw; what matters is that the request FAILS rather than
      // completing with a short file the client would believe was written.
      (e) => /UploadTooLarge|exceeds|terminated|aborted/i.test(`${e?.message} ${e?.cause?.message} ${e?.cause?.name}`),
    );
    assert.ok(seen.length === 0 || seen[0].body.length < 2048 + 512, "no complete body reached the server");
  });
});

test("UploadTooLarge is the error writeFileStream surfaces for an over-cap body", () => {
  const e = new UploadTooLarge(10);
  assert.equal(e.name, "UploadTooLarge");
  assert.match(e.message, /10/);
  assert.equal(typeof writeFileStream, "function");
});
