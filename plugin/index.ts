import * as crypto from 'crypto';
import net from 'net';
import { createClient } from 'spiffe';
import { definePluginEntry } from 'openclaw/plugin-sdk/plugin-entry';

// --- SPIFFE SVID WATCHER ---
let currentSpiffeId: string | null = null;
let signingKey: crypto.KeyObject | null = null;
let currentCertPem: string | null = null;

function derToPem(der: Uint8Array): string {
  const b64 = Buffer.from(der).toString('base64').match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`;
}

async function watchSvid(): Promise<void> {
  const client = createClient();
  try {
    const rpc = client.fetchX509SVID({});
    for await (const response of rpc.responses) {
      const svid = response.svids?.[0];
      if (!svid) continue;
      currentSpiffeId = svid.spiffeId?.toString() ?? null;
      signingKey = crypto.createPrivateKey({
        key: Buffer.from(svid.x509SvidKey),
        format: 'der',
        type: 'pkcs8',
      });
      currentCertPem = svid.x509Svid?.[0] ? derToPem(svid.x509Svid[0]) : null;
      console.log(`[Audit] SVID loaded: ${currentSpiffeId}`);
    }
  } catch (err) {
    console.error('[Audit] SVID stream ended, retrying in 5s:', (err as Error).message);
  } finally {
    // Clear identity when stream ends — fail closed until re-attested.
    currentSpiffeId = null;
    signingKey = null;
    currentCertPem = null;
    setTimeout(watchSvid, 5000);
  }
}

// --- OPA AUTHORIZATION ---
const OPA_URL = process.env.OPA_URL ?? 'http://opa:8181';
const OPA_POLICY_PATH = '/v1/data/openclaw/authz/allow';

async function isAuthorizedByOpa(spiffeId: string, toolName: string, params: unknown): Promise<boolean> {
  const response = await fetch(`${OPA_URL}${OPA_POLICY_PATH}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input: { spiffe_id: spiffeId, tool_name: toolName, params } }),
  });

  if (!response.ok) {
    throw new Error(`OPA returned HTTP ${response.status}`);
  }

  const body = await response.json() as { result?: boolean };
  return body.result === true;
}

// --- HASH CHAIN STATE ---
const GENESIS_HASH = '0'.repeat(64);
let previousHash: string = GENESIS_HASH;
let chainSequence: number = 0;

function hashPayload(payload: string): string {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

// --- TCP LOGGER SETUP ---
const SIEM_HOST = process.env.SIEM_HOST || 'fluentd-logger';
const SIEM_PORT = process.env.SIEM_PORT ? parseInt(process.env.SIEM_PORT) : 24224;

let tcpClient = new net.Socket();
let siemConnected = false;

function connectToSIEM() {
  tcpClient = new net.Socket();
  siemConnected = false;

  tcpClient.connect(SIEM_PORT, SIEM_HOST, () => {
    siemConnected = true;
    console.log(`[Audit] Connected to SIEM at ${SIEM_HOST}:${SIEM_PORT} via TCP`);
  });

  tcpClient.on('error', (err) => {
    siemConnected = false;
    console.error(`[Audit] SIEM TCP connection error:`, err.message);
  });

  tcpClient.on('close', () => {
    siemConnected = false;
    console.warn(`[Audit] SIEM connection closed. Reconnecting in 5s...`);
    setTimeout(connectToSIEM, 5000);
  });
}

connectToSIEM();

function sendSignedAuditLog(entry: object, key: crypto.KeyObject, certPem: string): void {
  if (!siemConnected || tcpClient.pending || tcpClient.destroyed) {
    throw new Error('SIEM TCP socket is not connected');
  }

  const chainedEntry = {
    ...entry,
    svid_cert: certPem,
    previousHash,
    sequence: chainSequence,
  };

  const payload = JSON.stringify(chainedEntry);
  const currentHash = hashPayload(payload);
  // Sign the hash hex string so verifiers can check against the stored hash
  // without needing to reconstruct the exact JSON serialization.
  const signature = crypto.sign('sha256', Buffer.from(currentHash), key).toString('base64');
  const message = Buffer.from(JSON.stringify({ payload: chainedEntry, hash: currentHash, signature }) + '\n');

  tcpClient.write(message);
  previousHash = currentHash;
  chainSequence += 1;
}

export default definePluginEntry({
  id: "spiffe-security-enforcer",
  name: "SPIFFE Zero Trust Enforcer",
  register(api) {
    api.on('gateway_start', async () => {
      watchSvid().catch((err) =>
        console.error('[Audit] Failed to start SVID watcher:', err)
      );
    });

    api.on('before_tool_call', async (event) => {
      console.log(`[Audit] Tool call intercepted: ${event.toolName}`);

      // Fail closed: no identity.
      if (!signingKey || !currentSpiffeId || !currentCertPem) {
        return { block: true, blockReason: 'Audit failure: SPIFFE SVID not yet available.' };
      }

      // Fail closed: OPA unavailable or denied.
      let opaDecision: boolean;
      try {
        opaDecision = await isAuthorizedByOpa(currentSpiffeId, event.toolName, event.params);
      } catch (error) {
        console.error('[Audit] OPA query failed:', error);
        return {
          block: true,
          blockReason: `Authorization failure: OPA unreachable (${error instanceof Error ? error.message : String(error)})`,
        };
      }

      // Fail closed: audit log must be written before allowing the call.
      try {
        sendSignedAuditLog({
          type: 'TOOL_POLICY_EVALUATION',
          spiffeId: currentSpiffeId,
          agentId: event.runId ?? 'unknown',
          toolName: event.toolName,
          params: event.params,
          opaDecision,
          timestamp: Date.now(),
        }, signingKey, currentCertPem);
        console.log(`[Audit] Log sent for tool: ${event.toolName}, allowed: ${opaDecision}`);
      } catch (error) {
        console.error('[Audit] Failed to send audit log:', error);
        return {
          block: true,
          blockReason: `Audit failure: could not write audit log (${error instanceof Error ? error.message : String(error)})`,
        };
      }

      if (!opaDecision) {
        return {
          block: true,
          blockReason: `Policy denied: identity ${currentSpiffeId} is not permitted to call tool '${event.toolName}'.`,
        };
      }
    }, { priority: 100 });
  },
});
