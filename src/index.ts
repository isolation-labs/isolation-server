// isolation-server — boot the gate: mint the master token if first run, start the HTTP
// surface, then bring up whatever the config prescribes (tunnel, heartbeat).
import { getToken } from "./config.js";
import { startConfigured, startServer } from "./server.js";
import { beatNow } from "./heartbeat.js";
import { tunnelManager } from "./tunnel.js";

getToken(); // ensure the token exists before anything can ask for it
// A quick-tunnel reconnect mints a new URL — report it to the cloud immediately.
tunnelManager.onUrlChange = () => beatNow();
startServer();
void startConfigured();
