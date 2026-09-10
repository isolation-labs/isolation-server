// The WebDAV mount, end to end, against a REAL Linux filesystem.
//
// Everything below the handler is stood up for real: a container holding /workspace, a fake execd
// that runs `/command` inside it with `docker exec` and serves `/files/*` off the bind mount, a fake
// opensandbox that resolves the endpoint, and the actual doorman in front. So the parts that no
// amount of type checking can vouch for — the `stat`/`find`/`df` output the listing is parsed from,
// `mv`/`cp`/`mkdir` against names with spaces and leading dashes, and the auth gate — are exercised
// as they will run in a sandbox rather than mocked into agreeing.
//
// Skipped when Docker or the sandbox tooling image is missing; it is a test, not a provisioner.
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { connect } from "node:net";
import { execFile, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const IMAGE = process.env.ISO_DAV_TEST_IMAGE ?? "isolation-server/tooling:0.7";

function dockerReady() {
  try {
    execFileSync("docker", ["image", "inspect", IMAGE], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const SKIP = dockerReady() ? false : `docker or the image ${IMAGE} is not available`;

// ── the fake sandbox stack ───────────────────────────────────────────────────────────────────────

const WORKSPACE = "/workspace";

/** execd's `/command`: run it inside the container and stream back execd's line-JSON events. */
function runInContainer(cid, { command, cwd, envs }, res) {
  const args = ["exec"];
  for (const [k, v] of Object.entries(envs ?? {})) args.push("-e", `${k}=${v}`);
  if (cwd) args.push("-w", cwd);
  args.push(cid, "sh", "-c", command);
  execFile("docker", args, { maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
    res.writeHead(200, { "Content-Type": "application/x-ndjson" });
    // One event per LINE, which is the shape execd emits and the shape run() reassembles.
    for (const line of String(stdout).split("\n")) if (line !== "") res.write(`${JSON.stringify({ type: "stdout", text: line })}\n`);
    for (const line of String(stderr).split("\n")) if (line !== "") res.write(`${JSON.stringify({ type: "stderr", text: line })}\n`);
    res.end(`${JSON.stringify(err ? { type: "error", text: String(err.code ?? 1) } : { type: "execution_complete" })}\n`);
  });
}

// The multipart execd receives, read back the way its Go parser would.
function parseMultipart(buf, boundary) {
  const sep = Buffer.from(`--${boundary}`);
  const parts = [];
  let i = buf.indexOf(sep);
  while (i !== -1) {
    const start = i + sep.length;
    if (buf.slice(start, start + 2).toString() === "--") break;
    const bodyStart = buf.indexOf("\r\n\r\n", start) + 4;
    const next = buf.indexOf(sep, bodyStart);
    if (next === -1) break;
    parts.push({ headers: buf.slice(start + 2, bodyStart - 4).toString("utf8"), body: buf.slice(bodyStart, next - 2) });
    i = next;
  }
  return parts;
}

let ctx;

before(async () => {
  if (SKIP) return;
  const home = mkdtempSync(join(tmpdir(), "iso-dav-home-"));
  const ws = mkdtempSync(join(tmpdir(), "iso-dav-ws-"));
  // A workspace with the awkward cases already in it: a space, a `#`, a leading dash, a symlink,
  // and a broken symlink (which must simply not appear).
  mkdirSync(join(ws, "sub"));
  writeFileSync(join(ws, "a.txt"), "hello world");
  writeFileSync(join(ws, "na me #1.txt"), "spaced");
  writeFileSync(join(ws, "sub", "-dash.txt"), "dashed");
  symlinkSync("a.txt", join(ws, "link.txt"));
  symlinkSync("/nowhere", join(ws, "broken.txt"));

  const cid = execFileSync("docker", ["run", "-d", "--rm", "-v", `${ws}:${WORKSPACE}`, "--entrypoint", "sh", IMAGE, "-c", "sleep 600"], {
    encoding: "utf8",
  }).trim();

  // Where a /workspace path lands on the host, through the bind mount.
  const hostPath = (p) => join(ws, p.slice(WORKSPACE.length).replace(/^\/+/, ""));

  const execd = createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    if (url.pathname === "/command" && req.method === "POST") {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => runInContainer(cid, JSON.parse(Buffer.concat(chunks).toString("utf8")), res));
      return;
    }
    if (url.pathname === "/files/download") {
      const p = hostPath(url.searchParams.get("path"));
      if (!existsSync(p)) return void res.writeHead(404).end();
      const body = readFileSync(p);
      // Deliberately IGNORE Range and answer 200: execd is not known to honour it, so the handler's
      // own slicing fallback is what has to be right. (ctx.rangeAware flips this for one test.)
      const range = ctx?.rangeAware ? /^bytes=(\d+)-(\d+)$/.exec(req.headers.range ?? "") : null;
      if (range) {
        const slice = body.subarray(Number(range[1]), Number(range[2]) + 1);
        return void res.writeHead(206, { "Content-Length": slice.length }).end(slice);
      }
      return void res.writeHead(200, { "Content-Length": body.length }).end(body);
    }
    if (url.pathname === "/files/upload" && req.method === "POST") {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const boundary = /boundary=(\S+)/.exec(req.headers["content-type"])[1];
        const parts = parseMultipart(Buffer.concat(chunks), boundary);
        const meta = JSON.parse(parts[0].body.toString("utf8"));
        writeFileSync(hostPath(meta.path), parts[1].body);
        res.writeHead(200).end("{}");
      });
      return;
    }
    res.writeHead(404).end();
  });
  execd.listen(0, "127.0.0.1");
  await once(execd, "listening");

  const osb = createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ endpoint: `127.0.0.1:${execd.address().port}` }));
  });
  osb.listen(0, "127.0.0.1");
  await once(osb, "listening");

  // config.ts reads HOME and the config file at import time, so both have to exist BEFORE the
  // first dist/ import below.
  process.env.ISOLATION_SERVER_HOME = home;
  mkdirSync(join(home, "data"), { recursive: true });
  writeFileSync(join(home, "config.json"), JSON.stringify({ token: "test-master-token", osb: { url: `http://127.0.0.1:${osb.address().port}`, apiKey: "" } }));
  const viewId = "v-davtest01";
  writeFileSync(
    join(home, "data", "views.json"),
    JSON.stringify({ [viewId]: { id: viewId, sandboxId: "sbx-test", type: "directory", port: 8081, label: "Files" } }),
  );

  const { handleViewRequest } = await import("../dist/doorman.js");
  const { davPassword } = await import("../dist/views.js");
  const front = createServer((req, res) => {
    void handleViewRequest(req, res).then((claimed) => {
      if (!claimed) res.writeHead(404).end();
    });
  });
  front.listen(0, "127.0.0.1");
  await once(front, "listening");

  ctx = {
    ws,
    cid,
    viewId,
    servers: [execd, osb, front],
    port: front.address().port,
    base: `http://127.0.0.1:${front.address().port}/v/${viewId}/dav`,
    auth: `Basic ${Buffer.from(`isolation:${davPassword(viewId)}`, "utf8").toString("base64")}`,
    rangeAware: false,
    home,
  };
});

after(() => {
  if (SKIP || !ctx) return;
  for (const s of ctx.servers) s.close();
  try {
    execFileSync("docker", ["rm", "-f", ctx.cid], { stdio: "ignore" });
  } catch {
    /* already gone */
  }
  rmSync(ctx.ws, { recursive: true, force: true });
  rmSync(ctx.home, { recursive: true, force: true });
});

const dav = (path, init = {}) =>
  fetch(`${ctx.base}${path}`, { ...init, headers: { Authorization: ctx.auth, ...(init.headers ?? {}) } });

describe("the files view mounts over WebDAV", { skip: SKIP }, () => {
  test("an unauthenticated request is challenged, so a file client knows to ask", async () => {
    const r = await fetch(`${ctx.base}/`, { method: "PROPFIND", headers: { Depth: "0" } });
    assert.equal(r.status, 401);
    assert.match(r.headers.get("www-authenticate") ?? "", /^Basic realm="Files"/);
  });

  test("a wrong password is refused", async () => {
    const r = await fetch(`${ctx.base}/`, {
      method: "PROPFIND",
      headers: { Depth: "0", Authorization: `Basic ${Buffer.from("isolation:nope").toString("base64")}` },
    });
    assert.equal(r.status, 401);
  });

  test("the mount password opens the mount and NOTHING else", async () => {
    // It never expires, so it must not be a way into the rest of the view. The view's own browser
    // surface (filebrowser, under the same /v/<id>) has to refuse it.
    const r = await fetch(`http://127.0.0.1:${ctx.port}/v/${ctx.viewId}/`, { headers: { Authorization: ctx.auth } });
    assert.equal(r.status, 401);
    // …and it is scoped to THIS view: another view's id must not accept it.
    const other = await fetch(`http://127.0.0.1:${ctx.port}/v/v-someother/dav/`, {
      method: "PROPFIND",
      headers: { Authorization: ctx.auth, Depth: "0" },
    });
    assert.equal(other.status, 404, "an unknown view is not even challenged");
  });

  test("OPTIONS advertises class 2, without which macOS mounts read-only", async () => {
    const r = await dav("/", { method: "OPTIONS" });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("dav"), "1, 2");
    assert.equal(r.headers.get("ms-author-via"), "DAV");
    for (const m of ["PROPFIND", "PROPPATCH", "MKCOL", "MOVE", "COPY", "LOCK", "UNLOCK", "PUT", "DELETE"]) {
      assert.match(r.headers.get("allow"), new RegExp(m));
    }
  });

  test("PROPFIND depth 1 lists the directory, with sizes, types and free space", async () => {
    const r = await dav("/", { method: "PROPFIND", headers: { Depth: "1", "Content-Type": "application/xml" }, body: "" });
    assert.equal(r.status, 207);
    const body = await r.text();
    // Names with a space and a `#` must come back percent-encoded in the href but intact in the
    // displayname — this is the pair a client uses to fetch the file it just listed.
    assert.match(body, new RegExp(`<D:href>/v/${ctx.viewId}/dav/na%20me%20%231.txt</D:href>`));
    assert.match(body, /<D:displayname>na me #1.txt<\/D:displayname>/);
    assert.match(body, new RegExp(`<D:href>/v/${ctx.viewId}/dav/sub/</D:href>`), "a collection href ends in a slash");
    assert.match(body, /<D:resourcetype><D:collection\/><\/D:resourcetype>/);
    assert.match(body, /<D:getcontentlength>11<\/D:getcontentlength>/, "a.txt is 11 bytes");
    assert.match(body, /<D:quota-available-bytes>\d+<\/D:quota-available-bytes>/, "macOS refuses copies without a quota");
    assert.doesNotMatch(body, /\de\+\d/, "byte counts must never come back in scientific notation");
    // A symlink is dereferenced; a BROKEN one simply is not there.
    assert.match(body, /<D:displayname>link.txt<\/D:displayname>/);
    assert.doesNotMatch(body, /broken\.txt/);
  });

  test("PROPFIND returns 404 propstat for properties it does not have", async () => {
    const body = `<?xml version="1.0"?><D:propfind xmlns:D="DAV:" xmlns:A="http://apple.com/ns/">
      <D:prop><D:getetag/><A:appledoubleheader/></D:prop></D:propfind>`;
    const r = await dav("/a.txt", { method: "PROPFIND", headers: { Depth: "0" }, body });
    const xml = await r.text();
    assert.match(xml, /<D:getetag>"[^"]+"<\/D:getetag>/, "an ETag keeps its literal quotes, as mod_dav emits it");
    // Under the CLIENT's namespace, not DAV: — a response that relabels it reads as malformed.
    assert.match(xml, /xmlns:n1="http:\/\/apple\.com\/ns\/"/);
    assert.match(xml, /<n1:appledoubleheader\/>[\s\S]*404 Not Found/);
  });

  test("PROPFIND depth infinity is refused rather than walking the tree", async () => {
    const r = await dav("/", { method: "PROPFIND", headers: { Depth: "infinity" } });
    assert.equal(r.status, 403);
    assert.match(await r.text(), /propfind-finite-depth/);
  });

  test("PROPFIND of a missing path is 404", async () => {
    assert.equal((await dav("/nope.txt", { method: "PROPFIND", headers: { Depth: "0" } })).status, 404);
  });

  test("a path that tries to leave the mount is refused", async () => {
    // `fetch` folds `..` out of a URL before it ever reaches the wire, so a traversal attempt has to
    // be written straight onto the socket — which is exactly what an attacker would do anyway.
    const raw = (line) =>
      new Promise((resolve, reject) => {
        const s = connect(ctx.port, "127.0.0.1", () => {
          s.write(`GET ${line} HTTP/1.1\r\nHost: 127.0.0.1\r\nDepth: 0\r\nAuthorization: ${ctx.auth}\r\nConnection: close\r\n\r\n`);
        });
        let buf = "";
        s.on("data", (c) => (buf += c));
        s.on("end", () => resolve({ status: Number(/^HTTP\/1\.1 (\d+)/.exec(buf)?.[1]), body: buf }));
        s.on("error", reject);
      });
    for (const p of ["/../../etc/passwd", "/sub/../../etc", "/%2e%2e/etc/passwd", "/sub/%2e%2e/%2e%2e/etc", "/..%2f..%2fetc"]) {
      const { status, body } = await raw(`/v/${ctx.viewId}/dav${p}`);
      assert.equal(status, 400, `${p} must not resolve`);
      assert.doesNotMatch(body, /root:/, `${p} must not have read anything outside the mount`);
    }
  });

  test("GET returns the bytes, an ETag, and never a document that could run", async () => {
    const r = await dav("/a.txt", {});
    assert.equal(r.status, 200);
    assert.equal(await r.text(), "hello world");
    assert.equal(r.headers.get("accept-ranges"), "bytes");
    assert.match(r.headers.get("content-security-policy") ?? "", /sandbox/);
    assert.equal(r.headers.get("x-content-type-options"), "nosniff");
    // A conditional GET the client already has the answer to.
    const etag = r.headers.get("etag");
    assert.equal((await dav("/a.txt", { headers: { "If-None-Match": etag } })).status, 304);
  });

  test("a Range is honoured even though execd answers with the whole file", async () => {
    ctx.rangeAware = false;
    const r = await dav("/a.txt", { headers: { Range: "bytes=6-10" } });
    assert.equal(r.status, 206);
    assert.equal(r.headers.get("content-range"), "bytes 6-10/11");
    assert.equal(await r.text(), "world");
    const suffix = await dav("/a.txt", { headers: { Range: "bytes=-5" } });
    assert.equal(await suffix.text(), "world");
    assert.equal((await dav("/a.txt", { headers: { Range: "bytes=99-200" } })).status, 416);
  });

  test("a Range execd DOES honour is passed through, not sliced twice", async () => {
    ctx.rangeAware = true;
    try {
      const r = await dav("/a.txt", { headers: { Range: "bytes=0-4" } });
      assert.equal(r.status, 206);
      assert.equal(await r.text(), "hello");
    } finally {
      ctx.rangeAware = false;
    }
  });

  test("PUT creates then overwrites, and the bytes land in the workspace", async () => {
    const created = await dav("/new.txt", { method: "PUT", body: "first" });
    assert.equal(created.status, 201);
    assert.equal(readFileSync(join(ctx.ws, "new.txt"), "utf8"), "first");
    const updated = await dav("/new.txt", { method: "PUT", body: "second" });
    assert.equal(updated.status, 204, "an overwrite is 204, not 201");
    assert.equal(readFileSync(join(ctx.ws, "new.txt"), "utf8"), "second");
  });

  test("PUT of a big body streams through without buffering it whole", async () => {
    const big = Buffer.alloc(5 * 1024 * 1024, 0x7a);
    const r = await dav("/big.bin", { method: "PUT", body: big });
    assert.equal(r.status, 201);
    assert.ok(readFileSync(join(ctx.ws, "big.bin")).equals(big));
  });

  test("the client droppings a mount scatters are accepted and never written", async () => {
    for (const name of [".DS_Store", "._a.txt", "Thumbs.db"]) {
      const r = await dav(`/${name}`, { method: "PUT", body: "junk" });
      assert.equal(r.status, 201, `${name} must look like it worked`);
      assert.equal(existsSync(join(ctx.ws, name)), false, `${name} must not reach the workspace`);
    }
    // …and they are invisible in a listing, so nothing tries to read one back.
    const body = await (await dav("/", { method: "PROPFIND", headers: { Depth: "1" } })).text();
    assert.doesNotMatch(body, /DS_Store/);
  });

  test("MKCOL creates a collection, and reports the two ways it can fail", async () => {
    assert.equal((await dav("/made", { method: "MKCOL" })).status, 201);
    assert.equal(existsSync(join(ctx.ws, "made")), true);
    assert.equal((await dav("/made", { method: "MKCOL" })).status, 405, "already exists");
    assert.equal((await dav("/absent/child", { method: "MKCOL" })).status, 409, "no parent collection");
  });

  test("MOVE and COPY handle names with spaces and leading dashes", async () => {
    const dest = (p) => `${ctx.base}${p}`;
    const moved = await dav("/na me #1.txt".replace(/ /g, "%20").replace(/#/g, "%23"), {
      method: "MOVE",
      headers: { Destination: dest("/made/-moved%20file.txt") },
    });
    assert.equal(moved.status, 201);
    assert.equal(readFileSync(join(ctx.ws, "made", "-moved file.txt"), "utf8"), "spaced");
    assert.equal(existsSync(join(ctx.ws, "na me #1.txt")), false);

    const copied = await dav("/made", { method: "COPY", headers: { Destination: dest("/made-copy") } });
    assert.equal(copied.status, 201);
    assert.equal(readFileSync(join(ctx.ws, "made-copy", "-moved file.txt"), "utf8"), "spaced");
  });

  test("MOVE refuses a destination outside the mount, and honours Overwrite: F", async () => {
    const outside = await dav("/a.txt", { method: "MOVE", headers: { Destination: "https://elsewhere.example/etc/passwd" } });
    assert.equal(outside.status, 502);
    const clash = await dav("/a.txt", { method: "MOVE", headers: { Destination: `${ctx.base}/new.txt`, Overwrite: "F" } });
    assert.equal(clash.status, 412);
    assert.equal(readFileSync(join(ctx.ws, "a.txt"), "utf8"), "hello world", "a refused move must not have happened");
  });

  test("LOCK, refresh and UNLOCK — the class-2 round trip a write goes through", async () => {
    const body = `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>
      <D:locktype><D:write/></D:locktype><D:owner>dani</D:owner></D:lockinfo>`;
    const locked = await dav("/new.txt", { method: "LOCK", headers: { Timeout: "Second-600" }, body });
    assert.equal(locked.status, 200);
    const token = /<([^>]+)>/.exec(locked.headers.get("lock-token"))[1];
    assert.match(token, /^opaquelocktoken:/);
    assert.match(await locked.text(), /<D:owner>dani<\/D:owner>/);

    // The lock now shows up in a PROPFIND, which is how a client learns who holds it.
    assert.match(await (await dav("/new.txt", { method: "PROPFIND", headers: { Depth: "0" } })).text(), new RegExp(token));

    // A second exclusive lock must be refused.
    assert.equal((await dav("/new.txt", { method: "LOCK", body })).status, 423);

    // An empty-bodied LOCK naming the token is a REFRESH.
    const refreshed = await dav("/new.txt", { method: "LOCK", headers: { If: `(<${token}>)`, Timeout: "Second-300" } });
    assert.equal(refreshed.status, 200);
    assert.equal((await dav("/new.txt", { method: "LOCK", headers: { If: "(<opaquelocktoken:bogus>)" } })).status, 412);

    assert.equal((await dav("/new.txt", { method: "UNLOCK", headers: { "Lock-Token": "<opaquelocktoken:bogus>" } })).status, 409);
    assert.equal((await dav("/new.txt", { method: "UNLOCK", headers: { "Lock-Token": `<${token}>` } })).status, 204);
  });

  test("LOCK on a path that does not exist yet creates it — clients lock before they PUT", async () => {
    const body = `<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`;
    const r = await dav("/notyet.txt", { method: "LOCK", body });
    assert.equal(r.status, 201);
    assert.equal(existsSync(join(ctx.ws, "notyet.txt")), true);
    await dav("/notyet.txt", { method: "UNLOCK", headers: { "Lock-Token": r.headers.get("lock-token") } });
  });

  test("PROPPATCH reports success for properties it drops, or Finder cannot write at all", async () => {
    const body = `<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:">
      <D:set><D:prop><Z:Win32LastModifiedTime>Tue, 09 Sep 2026 00:00:00 GMT</Z:Win32LastModifiedTime></D:prop></D:set></D:propertyupdate>`;
    const r = await dav("/new.txt", { method: "PROPPATCH", body });
    assert.equal(r.status, 207);
    const xml = await r.text();
    assert.match(xml, /200 OK/);
    assert.match(xml, /<n1:Win32LastModifiedTime\/>/);
  });

  test("DELETE removes a file and a whole tree", async () => {
    assert.equal((await dav("/new.txt", { method: "DELETE" })).status, 204);
    assert.equal(existsSync(join(ctx.ws, "new.txt")), false);
    assert.equal((await dav("/made-copy", { method: "DELETE" })).status, 204);
    assert.equal(existsSync(join(ctx.ws, "made-copy")), false);
    assert.equal((await dav("/new.txt", { method: "DELETE" })).status, 404);
    assert.equal((await dav("/", { method: "DELETE" })).status, 403, "the mount root is not deletable");
  });
});
