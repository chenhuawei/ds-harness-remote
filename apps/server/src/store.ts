import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { accountDeviceDescriptorSchema, type AccountDeviceDescriptor } from '@dsh-remote/protocol'
import { z } from 'zod'

export class ApiError extends Error {
  constructor(readonly code: string, readonly status = 400) { super(code) }
}
export const hash = (value: string): string => createHash('sha256').update(value).digest('hex')
export const secret = (): string => randomBytes(32).toString('base64url')
export const equal = (left: string, right: string): boolean => timingSafeEqual(Buffer.from(hash(left)), Buffer.from(hash(right)))

export interface AccountCredential { account: string; password: string }

/** Stable per-account key: trimmed and lowercased so one identity cannot be configured twice. */
export const accountKeyOf = (account: string): string => account.trim().toLowerCase()

const tokenSchema = z.object({
  kind: z.enum(['access', 'refresh']), deviceId: z.string(), expires: z.number(), used: z.boolean(),
  recovery: z.object({ nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/), accessExpires: z.number().int().positive() }).optional(),
})
const savedDeviceSchema = z.object({ accountId: z.string().min(1), descriptor: accountDeviceDescriptorSchema, revoked: z.boolean(), lastSeenAt: z.number() })
const accountRecordSchema = z.object({ account: z.string().min(1), salt: z.string(), verifier: z.string() })
// State v1 is the legacy single-account layout; it is migrated in place on first load.
const stateV1Schema = z.object({
  version: z.literal(1), account: z.string(), salt: z.string(), verifier: z.string(),
  devices: z.record(z.string(), savedDeviceSchema.omit({ accountId: true })), tokens: z.record(z.string(), tokenSchema),
})
const stateV2Schema = z.object({
  version: z.literal(2),
  accounts: z.record(z.string(), accountRecordSchema),
  devices: z.record(z.string(), savedDeviceSchema),
  tokens: z.record(z.string(), tokenSchema),
})
type SavedDevice = z.infer<typeof savedDeviceSchema>
type SavedToken = z.infer<typeof tokenSchema>

// Domain-separated HMACs keyed by the presented bearer, NOT its stored digest.
// The nonce alone cannot recover credentials from a copy of state.json.
function successor(token: string, nonce: string, deviceId: string) {
  const derive = (kind: string) => createHmac('sha256', token)
    .update(JSON.stringify(['ds-harness-remote/refresh/v1', deviceId, nonce, kind])).digest('base64url')
  return { accessToken: derive('access'), refreshToken: derive('refresh') }
}

function migrateV1(state: z.infer<typeof stateV1Schema>): z.infer<typeof stateV2Schema> {
  const key = accountKeyOf(state.account)
  return {
    version: 2,
    accounts: { [key]: { account: state.account, salt: state.salt, verifier: state.verifier } },
    devices: Object.fromEntries(Object.entries(state.devices).map(([id, device]) => [id, { accountId: key, descriptor: device.descriptor, revoked: device.revoked, lastSeenAt: device.lastSeenAt }])),
    tokens: state.tokens,
  }
}

/** Multi-account store. Only token digests and public identities reach disk. */
export class Store {
  private state: z.infer<typeof stateV2Schema>
  private readonly credentials = new Map<string, AccountCredential>()
  onInvalidate: (id: string) => void = () => {}

  constructor(private readonly file: string, accounts: readonly AccountCredential[] | string, password?: string) {
    const list: AccountCredential[] = typeof accounts === 'string' ? [{ account: accounts, password: password ?? '' }] : [...accounts]
    if (list.length === 0) throw new Error('At least one account is required.')
    for (const entry of list) {
      const key = accountKeyOf(entry.account)
      if (!key) throw new Error('Account names must not be empty.')
      if (this.credentials.has(key)) throw new Error(`Duplicate account "${entry.account.trim()}".`)
      this.credentials.set(key, entry)
    }
    let loaded: z.infer<typeof stateV2Schema> | undefined
    if (existsSync(file)) {
      const raw: unknown = JSON.parse(readFileSync(file, 'utf8'))
      const version = (raw as { version?: unknown }).version
      loaded = version === 1 ? migrateV1(stateV1Schema.parse(raw)) : stateV2Schema.parse(raw)
    }
    this.state = loaded ?? { version: 2, accounts: {}, devices: {}, tokens: {} }
    // Reconcile persisted accounts with the configured credentials: new accounts
    // get a fresh salt/verifier, a changed password drops only that account's
    // tokens, and a removed account loses its devices and tokens entirely.
    for (const [key, entry] of this.credentials) {
      const previous = this.state.accounts[key]
      const salt = previous?.salt ?? secret()
      const verifier = scryptSync(entry.password, salt, 32).toString('hex')
      this.state.accounts[key] = { account: entry.account.trim(), salt, verifier }
      if (!previous || !equal(previous.verifier, verifier)) this.dropAccountTokens(key)
    }
    for (const key of Object.keys(this.state.accounts)) {
      if (!this.credentials.has(key)) this.dropAccount(key)
    }
    // Orphan safety: a device or token without a surviving configured account can never authenticate.
    for (const [id, device] of Object.entries(this.state.devices)) {
      if (!this.credentials.has(device.accountId)) delete this.state.devices[id]
    }
    for (const [token, record] of Object.entries(this.state.tokens)) {
      const device = this.state.devices[record.deviceId]
      if (!device || !this.credentials.has(device.accountId)) delete this.state.tokens[token]
    }
    this.save()
  }

  private save(): void {
    mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 })
    const tmp = `${this.file}.tmp`
    writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 })
    renameSync(tmp, this.file)
  }

  /** Configured accounts as key → display name. */
  get accounts(): ReadonlyMap<string, string> {
    return new Map(Object.entries(this.state.accounts).map(([key, record]) => [key, record.account]))
  }

  /** Timing-safe login across every configured account; returns the account key or null. */
  verifyLogin(email: string, password: string): string | null {
    let matched: string | null = null
    for (const [key, entry] of this.credentials) {
      const accountOk = equal(email, entry.account.trim())
      const passwordOk = equal(password, entry.password)
      if (accountOk && passwordOk) matched = key
    }
    return matched
  }

  private accountDeviceIds(key: string): string[] {
    return Object.entries(this.state.devices).filter(([, device]) => device.accountId === key).map(([id]) => id)
  }

  private dropAccountTokens(key: string): void {
    const ids = new Set(this.accountDeviceIds(key))
    for (const [token, record] of Object.entries(this.state.tokens)) if (ids.has(record.deviceId)) delete this.state.tokens[token]
  }

  private dropAccount(key: string): void {
    this.dropAccountTokens(key)
    for (const id of this.accountDeviceIds(key)) delete this.state.devices[id]
    delete this.state.accounts[key]
  }

  get(id: string): SavedDevice {
    const d = Object.hasOwn(this.state.devices, id) ? this.state.devices[id] : undefined
    if (!d) throw new ApiError('DEVICE_NOT_FOUND', 404)
    if (d.revoked) throw new ApiError('DEVICE_REVOKED', 403)
    return d
  }
  list(): SavedDevice[] { return Object.values(this.state.devices).filter(d => !d.revoked) }
  register(descriptor: AccountDeviceDescriptor, accountKey?: string): ReturnType<Store['issue']> {
    const key = accountKey ?? (this.credentials.size === 1 ? this.credentials.keys().next().value! : undefined)
    if (!key || !this.credentials.has(key)) throw new ApiError('AUTH_INVALID', 403)
    const old = this.state.devices[descriptor.deviceId]
    if (old?.revoked) throw new ApiError('DEVICE_REVOKED', 403)
    // A deviceId moving between accounts is an identity conflict, never a silent transfer.
    if (old && (old.accountId !== key || old.descriptor.identityKey !== descriptor.identityKey || old.descriptor.role !== descriptor.role)) throw new ApiError('PEER_IDENTITY_MISMATCH', 409)
    // The cap counts active devices of this account only: revoked tombstones are kept but take no slot.
    if (!old && this.list().filter(d => d.accountId === key).length >= 256) throw new ApiError('RATE_LIMITED', 429)
    this.state.devices[descriptor.deviceId] = { accountId: key, descriptor, revoked: false, lastSeenAt: old?.lastSeenAt ?? 0 }
    this.invalidate(descriptor.deviceId)
    return this.issue(descriptor.deviceId)
  }
  private issue(deviceId: string, refreshTokenExpiresAt = Date.now() + 30 * 86400_000, previous?: { token: string; record: SavedToken }) {
    const tokens = { ...this.state.tokens }
    for (const [key, value] of Object.entries(tokens)) if (value.expires <= Date.now()) delete tokens[key]
    if (Object.keys(tokens).length + 2 > 16384) throw new ApiError('RATE_LIMITED', 429)
    const accessTokenExpiresAt = Date.now() + 60 * 60_000
    const nonce = secret()
    const { accessToken, refreshToken } = previous
      ? successor(previous.token, nonce, deviceId)
      : { accessToken: secret(), refreshToken: secret() }
    if (previous) tokens[hash(previous.token)] = {
      ...previous.record, used: true, recovery: { nonce, accessExpires: accessTokenExpiresAt },
    }
    tokens[hash(accessToken)] = { kind: 'access', deviceId, expires: accessTokenExpiresAt, used: false }
    tokens[hash(refreshToken)] = { kind: 'refresh', deviceId, expires: refreshTokenExpiresAt, used: false }
    const before = this.state.tokens
    this.state.tokens = tokens
    // Commit consumption, recovery metadata and the successor together. A failed
    // write must leave the previous token usable both in memory and after restart.
    try { this.save() } catch (error) { this.state.tokens = before; throw error }
    return { accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt }
  }
  authenticate(token: string): SavedDevice {
    const record = this.state.tokens[hash(token)]
    if (!record || record.kind !== 'access') throw new ApiError('AUTH_INVALID', 401)
    if (record.expires <= Date.now()) throw new ApiError('TOKEN_EXPIRED', 401)
    return this.get(record.deviceId)
  }
  refresh(deviceId: string, token: string) {
    this.get(deviceId)
    const record = this.state.tokens[hash(token)]
    if (!record || record.kind !== 'refresh' || record.deviceId !== deviceId) throw new ApiError('AUTH_INVALID', 401)
    if (record.expires <= Date.now()) throw new ApiError('TOKEN_EXPIRED', 401)
    if (!record.used) return this.issue(deviceId, record.expires, { token, record })
    // Legacy consumed tokens have no recovery record. Reject them without
    // invalidating credentials that may already be in use by this device.
    if (!record.recovery) throw new ApiError('AUTH_INVALID', 401)
    const pair = successor(token, record.recovery.nonce, deviceId)
    const next = this.state.tokens[hash(pair.refreshToken)]
    if (!next || next.kind !== 'refresh' || next.deviceId !== deviceId || next.expires !== record.expires) {
      throw new ApiError('INTERNAL_ERROR', 503)
    }
    if (next.used) throw new ApiError('AUTH_INVALID', 401)
    const access = this.state.tokens[hash(pair.accessToken)]
    if (access ? access.kind !== 'access' || access.deviceId !== deviceId || access.expires !== record.recovery.accessExpires
      : record.recovery.accessExpires > Date.now()) throw new ApiError('INTERNAL_ERROR', 503)
    // Return the original expiry, including an expired access bearer. The
    // recovered, still-valid refresh token can then rotate normally.
    return { ...pair, accessTokenExpiresAt: record.recovery.accessExpires, refreshTokenExpiresAt: next.expires }
  }
  invalidate(deviceId: string): void {
    for (const [key, value] of Object.entries(this.state.tokens)) if (value.deviceId === deviceId) delete this.state.tokens[key]
    this.onInvalidate(deviceId)
    this.save()
  }
  revoke(id: string): void { this.get(id).revoked = true; this.invalidate(id) }
  rename(id: string, name: string): void {
    this.get(id).descriptor.name = name
    this.save()
  }
  touch(id: string, clientVersion?: string, harnessVersion?: string): void {
    const d = this.get(id)
    d.lastSeenAt = Date.now()
    if (clientVersion) d.descriptor.clientVersion = clientVersion.slice(0, 64)
    if (d.descriptor.role === 'host' && harnessVersion) d.descriptor.harnessVersion = harnessVersion.slice(0, 64)
    this.save()
  }
}
