import { test, expect } from '@playwright/test';

const URL = "http://localhost:6891/";
const toSign = [1, 2, 3, 4, 5]

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.beehive)
});

test.describe("SigningKey", async () => {
  test('constructor', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { SigningKey } = window.beehive
      const bytes = new Uint8Array(32)
      const key = new SigningKey(bytes)
      return { key }
    })

    expect(out.key).toBeDefined()
  })

  test('verifyingKey', async ({ page }) => {
    const out = await page.evaluate((input) => {
      const { SigningKey } = window.beehive
      const key = new SigningKey(new Uint8Array(32))
      return { input, key, vKey: key.verifyingKey }
    }, { toSign })

    expect(out.vKey).toBeDefined()
  })

  test('trySign', async ({ page }) => {
    const out = await page.evaluate((input) => {
      const { SigningKey } = window.beehive
      const key = new SigningKey(new Uint8Array(32))
      const signed = key.trySign(new Uint8Array(input.toSign))
      const { payload, verifyingKey, signature } = signed
      return { input, payload, verifyingKey, signature, key }
    }, { toSign })

    expect(out.signature).toBeDefined()
    expect(Object.values(out.payload)).toStrictEqual(toSign)
  })
})

test.describe("Signed", async () => {
  test('verify', async ({ page }) => {
    const out = await page.evaluate((input) => {
      const { SigningKey } = window.beehive
      const key = new SigningKey(new Uint8Array(32))
      const signed = key.trySign(new Uint8Array(input.toSign))
      const { payload, verifyingKey, signature } = signed
      const verified = signed.verify()
      return { input, payload, verifyingKey, signature, verified, key }
    }, { toSign })

    expect(out.verified).toBe(true)
  })

  test('payload', async ({ page }) => {
    const out = await page.evaluate((input) => {
      const { SigningKey } = window.beehive
      const key = new SigningKey(new Uint8Array(32))
      const signed = key.trySign(new Uint8Array(input.toSign))
      const { payload, verifyingKey, signature } = signed
      return { input, payload, verifyingKey, signature, key }
    }, { toSign })

    expect(Object.values(out.payload)).toStrictEqual(toSign)
  })

  test('signature', async ({ page }) => {
    const out = await page.evaluate((input) => {
      const { SigningKey } = window.beehive
      const key = new SigningKey(new Uint8Array(32))
      const signed = key.trySign(new Uint8Array(input.toSign))
      const { payload, signature } = signed
      return { input, payload, signature }
    }, { toSign })

    expect(out.signature).toBeDefined()
    expect(Object.values(out.payload)).toStrictEqual(toSign)
  })
})

test.describe("Beehive", async () => {
  test('constructor', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, SigningKey } = window.beehive
      const bytes = new Uint8Array(32)
      return { beehive: new Beehive(new SigningKey(bytes)) }
    })

    expect(out.beehive).toBeDefined()
  })

  test('id', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, SigningKey } = window.beehive
      const key = new SigningKey(new Uint8Array(32))
      const vKey = key.verifyingKey
      const beehive = new Beehive(key)
      return { id: beehive.id, vKey }
    })

    expect(out.id).toStrictEqual(out.vKey)
  })

  test('idString', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, SigningKey } = window.beehive
      const key = new SigningKey(new Uint8Array(32))
      const vKey = key.verifyingKey
      const beehive = new Beehive(key)
      return { idString: beehive.idString, vKey }
    })

    expect(out.idString).toBeDefined()
    expect(out.idString).toHaveLength(65)
    expect(out.idString.slice(0, 2)).toStrictEqual('0x')
    expect(out.idString).toStrictEqual('0x3b6a27bcceb6a42d62a3a8d02a6fd73653215771de243a63ac048a18b59da29')
  })

  test('generateGroup', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, SigningKey } = window.beehive
      const key = new SigningKey(new Uint8Array(32))
      const beehive = new Beehive(key)

      const group = beehive.generateGroup([])
      const { groupId, members } = group
      const canStr = members[0].can.toString()
      return { group, groupId, members, canStr }
    })

    expect(out.group).toBeDefined()
    expect(out.groupId).toBeDefined()
    expect(out.members).toHaveLength(1)
    expect(out.canStr).toStrictEqual('Admin')
  })
})
