// A small markdown → HTML renderer for agent replies: fenced code, headings, lists, quotes,
// paragraphs, inline code/bold/italic/links. Everything is HTML-escaped first; the only tags
// emitted are ours. Not a full CommonMark — enough for what coding agents write.
const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function inline(s: string): string {
  let out = "";
  let i = 0;
  const codeSpans: string[] = [];
  // Protect code spans from the other rules. The placeholder is NUL-delimited, so a NUL the
  // agent's own text carries is stripped first — otherwise it could name someone else's span.
  s = s.replace(/\u0000/g, "").replace(/`([^`]+)`/g, (_m, c: string) => {
    codeSpans.push(`<code>${esc(c)}</code>`);
    return `\u0000${codeSpans.length - 1}\u0000`;
  });
  out = esc(s)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*\w])\*([^*\n]+)\*(?=[^*\w]|$)/g, "$1<em>$2</em>")
    .replace(/(^|[^_\w])_([^_\n]+)_(?=[^_\w]|$)/g, "$1<em>$2</em>")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer noopener">$1</a>')
    .replace(/(^|\s)(https?:\/\/[^\s<]+[^\s<.,;:)])/g, '$1<a href="$2" target="_blank" rel="noreferrer noopener">$2</a>');
  void i;
  return out.replace(/\u0000(\d+)\u0000/g, (_m, k: string) => codeSpans[Number(k)] ?? "");
}

// --- workspace file links --------------------------------------------------------
// Paths the agent mentions become links the page turns into "open in the code view"
// (main.tsx posts `isolation:open-file` to the embedding SPA). Absolute `/workspace/…` paths
// always link; a relative path links when it has a directory part; a bare `Name.ext:17` links
// when an absolute path with that basename appeared earlier in the same message.
// The `/workspace/…` arm must not swallow trailing punctuation (`…/App.tsx.` at the end of a
// sentence would lose its extension and stop linking) — so it ends on a name character.
const PATH_RE = /(?<![\w/.-])(\/workspace\/[\w.@+-](?:[\w.@+\/-]*[\w@+])?|(?:[\w.@+-]+\/)+[\w.@+-]+\.[A-Za-z0-9]{1,8}|[\w.@+-]+\.[A-Za-z0-9]{1,8})(?::(\d+))?(?::\d+)?(?![\w/])/g;

// Files the conversation has touched (tool-call locations, absolute paths already cited), by
// basename — so a later bare `App.tsx:17` still resolves to `cv/src/App.tsx`.
const knownFiles = new Map<string, string>();
export function rememberFile(path: string): void {
  const rel = path.replace(/^\/workspace\//, "").replace(/^\.\//, "");
  if (rel && !rel.startsWith("/")) knownFiles.set(rel.split("/").pop() ?? rel, rel);
}

function linkify(html: string, seen: Map<string, string>): string {
  // Only text nodes and code spans are candidates; anchors/pre blocks stay as they are.
  return html.replace(/(<a\b[^>]*>[\s\S]*?<\/a>|<pre\b[\s\S]*?<\/pre>)|(<code>)([\s\S]*?)(<\/code>)|([^<]+)/g, (m, keep: string | undefined, o: string | undefined, code: string | undefined, c: string | undefined, text: string | undefined) => {
    if (keep) return keep;
    const body = code ?? text ?? "";
    const out = body.replace(PATH_RE, (whole, path: string, line: string | undefined) => {
      let rel: string | undefined;
      if (path.startsWith("/workspace/")) {
        rel = path.slice("/workspace/".length);
        seen.set(rel.split("/").pop() ?? rel, rel);
        rememberFile(rel);
      } else if (path.includes("/")) rel = path.replace(/^\.\//, "");
      else rel = seen.get(path) ?? knownFiles.get(path);
      // Nothing outside the workspace root: the code view rejects `..` segments anyway.
      if (!rel || rel.startsWith("/") || rel.split("/").includes("..")) return whole;
      if (!/\.[A-Za-z0-9]{1,8}$/.test(rel)) return whole;
      // A span, not an anchor: nothing to navigate to — the click posts to the embedding SPA.
      return `<span class="file-link" role="link" tabindex="0" data-file="${esc(rel)}"${line ? ` data-line="${line}"` : ""} title="Open in the code view">${whole}</span>`;
    });
    return code ? `${o}${out}${c}` : out;
  });
}

export function renderMarkdown(src: string): string {
  const seen = new Map<string, string>();
  return linkify(renderBlocks(src), seen);
}

function renderBlocks(src: string): string {
  const lines = src.replace(/\r\n?/g, "\n").split("\n");
  const html: string[] = [];
  let i = 0;
  let para: string[] = [];
  const flush = () => {
    if (para.length) {
      html.push(`<p>${inline(para.join("\n"))}</p>`);
      para = [];
    }
  };
  while (i < lines.length) {
    const line = lines[i];
    const fence = /^\s*```\s*([\w.+-]*)\s*$/.exec(line);
    if (fence) {
      flush();
      const lang = fence[1];
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) body.push(lines[i++]);
      i++; // closing fence
      html.push(`<pre${lang ? ` data-lang="${esc(lang)}"` : ""}><code>${esc(body.join("\n"))}</code></pre>`);
      continue;
    }
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      flush();
      const n = Math.min(h[1].length + 1, 6);
      html.push(`<h${n}>${inline(h[2])}</h${n}>`);
      i++;
      continue;
    }
    if (/^\s*([-*+]|\d+\.)\s+/.test(line)) {
      flush();
      const ordered = /^\s*\d+\./.test(line);
      const items: string[] = [];
      while (i < lines.length && /^\s*([-*+]|\d+\.)\s+/.test(lines[i])) {
        let item = lines[i].replace(/^\s*([-*+]|\d+\.)\s+/, "");
        i++;
        // Continuation lines (indented) belong to the item.
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*+]|\d+\.)\s+/.test(lines[i])) item += `\n${lines[i++].trim()}`;
        const task = /^\[([ xX])\]\s+(.*)$/.exec(item);
        items.push(task ? `<li class="task${task[1] === " " ? "" : " done"}">${inline(task[2])}</li>` : `<li>${inline(item)}</li>`);
      }
      html.push(`<${ordered ? "ol" : "ul"}>${items.join("")}</${ordered ? "ol" : "ul"}>`);
      continue;
    }
    if (/^\s*>\s?/.test(line)) {
      flush();
      const q: string[] = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) q.push(lines[i++].replace(/^\s*>\s?/, ""));
      html.push(`<blockquote>${renderBlocks(q.join("\n"))}</blockquote>`);
      continue;
    }
    if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      flush();
      html.push("<hr>");
      i++;
      continue;
    }
    if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
      flush();
      const rows: string[][] = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
        const cells = lines[i].trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
        if (!cells.every((c) => /^:?-{2,}:?$/.test(c))) rows.push(cells);
        i++;
      }
      const [head, ...body] = rows;
      html.push(`<table><thead><tr>${(head ?? []).map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead><tbody>${body.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
      continue;
    }
    if (!line.trim()) {
      flush();
      i++;
      continue;
    }
    para.push(line);
    i++;
  }
  flush();
  return html.join("\n");
}
