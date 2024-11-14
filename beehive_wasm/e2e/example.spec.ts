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
      const key = SigningKey.generate()
      return { key }
    })

    expect(out.key).toBeDefined()
  })

  test('verifyingKey', async ({ page }) => {
    const out = await page.evaluate((input) => {
      const { SigningKey } = window.beehive
      const key = SigningKey.generate()
      return { input, key, vKey: key.verifyingKey }
    }, { toSign })

    expect(out.vKey).toBeDefined()
  })

  test('trySign', async ({ page }) => {
    const out = await page.evaluate((input) => {
      const { SigningKey } = window.beehive
      const key = SigningKey.generate()
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
      const key = SigningKey.generate()
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
      const key = SigningKey.generate()
      const signed = key.trySign(new Uint8Array(input.toSign))
      const { payload, verifyingKey, signature } = signed
      return { input, payload, verifyingKey, signature, key }
    }, { toSign })

    expect(Object.values(out.payload)).toStrictEqual(toSign)
  })

  test('signature', async ({ page }) => {
    const out = await page.evaluate((input) => {
      const { SigningKey } = window.beehive
      const key = SigningKey.generate()
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
      return { beehive: new Beehive(SigningKey.generate()) }
    })

    expect(out.beehive).toBeDefined()
  })

  test('id', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, SigningKey } = window.beehive
      const key = SigningKey.generate()
      const vKey = key.verifyingKey
      const beehive = new Beehive(key)
      return { id: beehive.id, vKey }
    })

    expect(out.id).toStrictEqual(out.vKey)
  })

  test('idString', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, SigningKey } = window.beehive
      const key = SigningKey.generate()
      const vKey = key.verifyingKey
      const beehive = new Beehive(key)
      return { idString: beehive.idString, vKey }
    })

    expect(out.idString).toBeDefined()
    expect(out.idString.length).toBeLessThanOrEqual(66)
    expect(out.idString.slice(0, 2)).toStrictEqual('0x')
    expect(out.idString).toMatch(/0x[0-9a-fA-F]+/) // Hex
  })

  test('generateGroup', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, SigningKey } = window.beehive
      const beehive = new Beehive(SigningKey.generate())

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
