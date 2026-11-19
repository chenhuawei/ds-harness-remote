import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { z } from 'zod'
import {
  createRemoteServer,
  parseHelloTimeout,
  parseHeartbeatInterval,
  parseHeartbeatDisconnect,
  parseForceTerminateGrace,
  parseMaxFramesPerSec,
} from './server.js'
import { parseLogLevel } from './logger.js'
import { parseIceConfig } from './ice.js'
import type { AccountCredential } from './store.js'

const accountEntrySchema = z.object({ account: z.string().min(1), password: z.string().min(1) }).strict()

/**
 * Account sources, first match wins:
 *  1. DSH_SERVER_ACCOUNTS_FILE — JSON array of {account, password} (volume-friendly)
 *  2. DSH_SERVER_ACCOUNTS      — the same JSON array inline in the environment
 *  3. DSH_SERVER_ACCOUNT + DSH_SERVER_PASSWORD — legacy single account
 */
function parseAccountsFromEnv(): AccountCredential[] {
  const file = process.env.DSH_SERVER_ACCOUNTS_FILE?.trim()
  if (file) {
    const path = resolve(file)
    if (!existsSync(path)) throw new Error(`DSH_SERVER_ACCOUNTS_FILE points to a missing file: ${file}`)
    const parsed = z.array(accountEntrySchema).parse(JSON.parse(readFileSync(path, 'utf8')))
    if (parsed.length === 0) throw new Error('DSH_SERVER_ACCOUNTS_FILE must list at least one account.')
    return parsed
  }
  const inline = process.env.DSH_SERVER_ACCOUNTS?.trim()
  if (inline) {
    const parsed = z.array(accountEntrySchema).parse(JSON.parse(inline))
    if (parsed.length === 0) throw new Error('DSH_SERVER_ACCOUNTS must list at least one account.')
    return parsed
  }
  return [{ account: process.env.DSH_SERVER_ACCOUNT ?? '', password: process.env.DSH_SERVER_PASSWORD ?? '' }]
}

const port = Number(process.env.DSH_SERVER_PORT ?? '8080')
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid DSH_SERVER_PORT.')

const heartbeatIntervalMs = parseHeartbeatInterval(process.env.DSH_SERVER_HEARTBEAT_INTERVAL_MS)
const heartbeatDisconnectMs = parseHeartbeatDisconnect(process.env.DSH_SERVER_HEARTBEAT_DISCONNECT_MS, heartbeatIntervalMs)
const helloTimeoutMs = parseHelloTimeout(process.env.DSH_SERVER_HELLO_TIMEOUT_MS)
const forceTerminateGraceMs = parseForceTerminateGrace(process.env.DSH_SERVER_FORCE_TERMINATE_GRACE_MS)
const maxFramesPerSec = parseMaxFramesPerSec(process.env.DSH_SERVER_MAX_FRAMES_PER_SEC)
const logLevel = parseLogLevel(process.env.DSH_SERVER_LOG_LEVEL)

const app = createRemoteServer({
  accounts: parseAccountsFromEnv(),
  publicUrl: process.env.DSH_SERVER_PUBLIC_URL ?? `http://localhost:${port}`,
  dataFile: resolve(process.env.DSH_SERVER_DATA_FILE ?? 'data/state.json'),
  trustedProxyIps: (process.env.DSH_SERVER_TRUSTED_PROXY_IPS ?? '').split(',').map(value => value.trim()).filter(Boolean),
  helloTimeoutMs,
  heartbeatIntervalMs,
  heartbeatDisconnectMs,
  forceTerminateGraceMs,
  maxFramesPerSec,
  logLevel,
  ice: parseIceConfig(process.env),
  attentionWebhookUrl: process.env.DSH_SERVER_ATTENTION_WEBHOOK_URL,
})
app.server.listen(port, process.env.DSH_SERVER_HOST ?? '127.0.0.1', () => console.info(`Remote Server listening on port ${port}`))
app.server.on('error', () => { console.error('Remote Server could not listen. Check address and port.'); process.exitCode = 1; app.gateway.close() })
let stopping = false
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  if (stopping) return
  stopping = true
  void app.close().then(() => { process.exitCode = 0 }, () => { process.exitCode = 1 })
})
