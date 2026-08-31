// The package's own version — read from package.json (dist/ ships one level under it),
// so the number on npm IS the number every surface reports. Fallback covers dev runs.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const GATE_VERSION = ((): string => {
  try {
    const pkg = JSON.parse(readFileSync(join(fileURLToPath(new URL(".", import.meta.url)), "..", "package.json"), "utf8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
})();
