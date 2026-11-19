import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { WebSocket } from 'ws'
import { createControlFrame } from '@dsh-remote/protocol'
import { generateKeyPair } from '../../../packages/crypto/src/index.js'
import { createRemoteServer, type Config } from '../src/server.js'

const alice = { account: 'alice@example.com', password: 'alice-password-123' }
const bob = { account: 'bob@example.com', password: 'bob-password-12345' }
const fullCapabilities = ['transport.lan', 'transport.p2p', 'transport.turn', 'transport.relay']

let app: ReturnType<typeof createRemoteServer>, dir: string, base: string
const sockets: WebSocket[] = []

async function request(path: string, method = 'GET', body?: unknown, token?: string) {
  const response = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
  return { status: response.status, data: await response.json() }
}

async function start(config: Partial<Config> & { dataFile: string }) {
  app = createRemoteServer({ publicUrl: 'http://localhost:8080', ...config } as Config)
  app.server.listen(0, '127.0.0.1')
  await once(app.server, 'listening')
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
}

async function login(account: string, password: string): Promise<string> {
  const result = await request('/auth/login', 'POST', { email: account, password })
  expect(result.status).toBe(200)
  return result.data.token
}

async function registerDevice(accountToken: string, role: 'host' | 'client') {
  const descriptor = { deviceId: randomUUID(), identityKey: generateKeyPair().publicKey, name: `${role}-device`, role, platform: 'linux', clientVersion: '0.6.5' }
  const result = await request('/devices/register', 'POST', { v: 1, device: descriptor }, accountToken)
  expect(result.status).toBe(200)
  return { descriptor, accessToken: result.data.accessToken as string }
}

class Wire {
  messages: { type: string; payload: any }[] = []
  constructor(readonly ws: WebSocket) { ws.on('message', raw => this.messages.push(JSON.parse(raw.toString()))) }
  send(type: Parameters<typeof createControlFrame>[0], payload: unknown) { this.ws.send(JSON.stringify(createControlFrame(type, payload))) }
  async next(type: string): Promise<any> {
    const until = Date.now() + 3000
    while (Date.now() < until) {
      const index = this.messages.findIndex(message => message.type === type)
      if (index >= 0) return this.messages.splice(index, 1)[0]!.payload
      await new Promise(resolve => setTimeout(resolve, 25))
    }
    throw new Error(`Missing frame ${type}`)
  }
}

async function connectDevice(device: { descriptor: { deviceId: string; role: string } }, accessToken: string): Promise<Wire> {
  const ws = new WebSocket(`${base.replace('http', 'ws')}/ws/v1/connect`)
  sockets.push(ws)
  await once(ws, 'open')
  const wire = new Wire(ws)
  wire.send('hello', { deviceId: device.descriptor.deviceId, role: device.descriptor.role, accessToken, protocols: [1], capabilities: fullCapabilities, clientVersion: '0.6.5' })
  await wire.next('hello.ack')
  return wire
}

beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'dsh-multi-')) })
afterEach(async () => {
  for (const ws of sockets.splice(0)) ws.close()
  if (app) await app.close()
  rmSync(dir, { recursive: true, force: true })
})

describe('multi-account server', () => {
  it('logs each account in and reports its own profile', async () => {
    await start({ accounts: [alice, bob], dataFile: join(dir, 'state.json') })
    const aliceToken = await login(alice.account, alice.password)
    const bobToken = await login(bob.account, bob.password)
    expect((await request('/auth/me', 'GET', undefined, aliceToken)).data.account).toBe(alice.account)
    expect((await request('/auth/me', 'GET', undefined, bobToken)).data.account).toBe(bob.account)
    const bad = await request('/auth/login', 'POST', { email: alice.account, password: 'wrong-password-1' })
    expect(bad.status).toBe(401)
    expect(bad.data.error.code).toBe('AUTH_INVALID')
  })

  it('scopes web device lists and host discovery to the same account', async () => {
    await start({ accounts: [alice, bob], dataFile: join(dir, 'state.json') })
    const aliceToken = await login(alice.account, alice.password)
    const bobToken = await login(bob.account, bob.password)
    const aliceHost = await registerDevice(aliceToken, 'host')
    const aliceClient = await registerDevice(aliceToken, 'client')
    const bobHost = await registerDevice(bobToken, 'host')

    const aliceDevices = await request('/account/devices', 'GET', undefined, aliceToken)
    expect(aliceDevices.data.items.map((item: any) => item.deviceId).sort()).toEqual([aliceHost.descriptor.deviceId, aliceClient.descriptor.deviceId].sort())
    const bobDevices = await request('/account/devices', 'GET', undefined, bobToken)
    expect(bobDevices.data.items.map((item: any) => item.deviceId)).toEqual([bobHost.descriptor.deviceId])

    const hosts = await request('/devices', 'GET', undefined, aliceClient.accessToken)
    expect(hosts.data.items.map((item: any) => item.deviceId)).toEqual([aliceHost.descriptor.deviceId])
  })

  it('rejects cross-account device lookup and rename', async () => {
    await start({ accounts: [alice, bob], dataFile: join(dir, 'state.json') })
    const aliceToken = await login(alice.account, alice.password)
    const bobToken = await login(bob.account, bob.password)
    const aliceClient = await registerDevice(aliceToken, 'client')
    const bobHost = await registerDevice(bobToken, 'host')

    const lookup = await request(`/devices/${bobHost.descriptor.deviceId}`, 'GET', undefined, aliceClient.accessToken)
    expect(lookup.status).toBe(403)
    expect(lookup.data.error.code).toBe('MEMBERSHIP_REQUIRED')

    const rename = await request(`/devices/${bobHost.descriptor.deviceId}/name`, 'POST', { name: 'hijacked' }, aliceToken)
    expect(rename.status).toBe(404)
    expect(rename.data.error.code).toBe('DEVICE_NOT_FOUND')
  })

  it('rejects cross-account device revocation but allows revoking own devices', async () => {
    await start({ accounts: [alice, bob], dataFile: join(dir, 'state.json') })
    const aliceToken = await login(alice.account, alice.password)
    const bobToken = await login(bob.account, bob.password)
    const aliceClient = await registerDevice(aliceToken, 'client')
    const bobHost = await registerDevice(bobToken, 'host')

    // Alice's web session must not revoke Bob's device: it looks like an unknown device and stays usable.
    const cross = await request(`/account/devices/${bobHost.descriptor.deviceId}`, 'DELETE', undefined, aliceToken)
    expect(cross.status).toBe(404)
    expect(cross.data.error.code).toBe('DEVICE_NOT_FOUND')
    expect((await request('/me', 'GET', undefined, bobHost.accessToken)).status).toBe(200)

    // Revoking a device of the own account still works and blocks its credentials.
    const revoked = await request(`/account/devices/${aliceClient.descriptor.deviceId}`, 'DELETE', undefined, aliceToken)
    expect(revoked.status).toBe(200)
    expect(revoked.data.status).toBe('revoked')
    const stale = await request('/me', 'GET', undefined, aliceClient.accessToken)
    expect(stale.status).toBe(401)
    expect(stale.data.error.code).toBe('AUTH_INVALID')
  })

  it('blocks cross-account connect.request and allows same-account connections', async () => {
    await start({ accounts: [alice, bob], dataFile: join(dir, 'state.json') })
    const aliceToken = await login(alice.account, alice.password)
    const bobToken = await login(bob.account, bob.password)
    const aliceHost = await registerDevice(aliceToken, 'host')
    const aliceClient = await registerDevice(aliceToken, 'client')
    const bobHost = await registerDevice(bobToken, 'host')

    const aliceHostWire = await connectDevice(aliceHost, (await request('/devices/register', 'POST', { v: 1, device: aliceHost.descriptor }, aliceToken)).data.accessToken)
    const aliceClientWire = await connectDevice(aliceClient, aliceClient.accessToken)
    const bobHostWire = await connectDevice(bobHost, (await request('/devices/register', 'POST', { v: 1, device: bobHost.descriptor }, bobToken)).data.accessToken)

    // Cross-account: alice's client must not reach bob's host.
    aliceClientWire.send('connect.request', { hostDeviceId: bobHost.descriptor.deviceId, preferredTransports: ['relay'] })
    const blocked = await aliceClientWire.next('error')
    expect(blocked.code).toBe('MEMBERSHIP_REQUIRED')

    // Same account: alice's client reaches alice's host.
    const freshAliceClient = await registerDevice(aliceToken, 'client')
    const freshWire = await connectDevice(freshAliceClient, freshAliceClient.accessToken)
    freshWire.send('connect.request', { hostDeviceId: aliceHost.descriptor.deviceId, preferredTransports: ['relay'] })
    const incoming = await aliceHostWire.next('connect.incoming')
    expect(incoming.clientDeviceId).toBe(freshAliceClient.descriptor.deviceId)
    expect(incoming.authorization).toBe('account')
    bobHostWire.ws.close()
  })

  it('migrates a v1 single-account state file and keeps its devices working', async () => {
    const dataFile = join(dir, 'state.json')
    // Boot once with the legacy single-account config, register alice's device.
    await start({ account: alice.account, password: alice.password, dataFile })
    const legacyToken = await login(alice.account, alice.password)
    const device = await registerDevice(legacyToken, 'client')
    await app.close()
    // Reboot multi-account with the same first account plus bob.
    await start({ accounts: [alice, bob], dataFile })
    const me = await request('/me', 'GET', undefined, device.accessToken)
    expect(me.status).toBe(200)
    expect(me.data.membershipId).toMatch(/^account:/)
    const aliceToken = await login(alice.account, alice.password)
    const devices = await request('/account/devices', 'GET', undefined, aliceToken)
    expect(devices.data.items.map((item: any) => item.deviceId)).toEqual([device.descriptor.deviceId])
  })

  it('drops removed accounts and invalidates tokens only for changed passwords', async () => {
    const dataFile = join(dir, 'state.json')
    await start({ accounts: [alice, bob], dataFile })
    const aliceToken = await login(alice.account, alice.password)
    const bobToken = await login(bob.account, bob.password)
    const aliceDevice = await registerDevice(aliceToken, 'client')
    const bobDevice = await registerDevice(bobToken, 'client')
    await app.close()

    // Remove bob from the configuration: his tokens and devices must disappear entirely.
    await start({ accounts: [alice], dataFile })
    const bobGone = await request('/me', 'GET', undefined, bobDevice.accessToken)
    expect(bobGone.status).toBe(401)
    expect(bobGone.data.error.code).toBe('AUTH_INVALID')
    expect((await request('/me', 'GET', undefined, aliceDevice.accessToken)).status).toBe(200)
    await app.close()

    // Change alice's password: only her tokens are dropped, the device record survives.
    await start({ accounts: [{ account: alice.account, password: 'rotated-password-1' }], dataFile })
    expect((await request('/me', 'GET', undefined, aliceDevice.accessToken)).status).toBe(401)
    const relogin = await login(alice.account, 'rotated-password-1')
    const devices = await request('/account/devices', 'GET', undefined, relogin)
    expect(devices.data.items.map((item: any) => item.deviceId)).toEqual([aliceDevice.descriptor.deviceId])
  })
})
