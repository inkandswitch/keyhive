import { test, expect } from '@playwright/test';

const URL = "http://localhost:6891/";
const toSign = [1, 2, 3, 4, 5]

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.beehive)
});

test.describe("SigningKey", async () => {
  test.describe('constructor', async () => {
    const scenario = () => {
      const { SigningKey } = window.beehive
      const key = SigningKey.generate()
      return { key }
    }

    test('initializes successfully', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.key).toBeDefined()
    })
  })

  test.describe('verifyingKey', async () => {
    const scenario = (input) => {
      const { SigningKey } = window.beehive
      const key = SigningKey.generate()
      return { input, key, vKey: key.verifyingKey }
    }

    test('has a verifying key', async ({ page }) => {
      const out = await page.evaluate(scenario, { toSign })
      expect(out.vKey).toBeDefined()
    })
  })

  test.describe('trySign', async () => {
    const scenario = (input) => {
      const { SigningKey } = window.beehive
      const key = SigningKey.generate()
      const signed = key.trySign(new Uint8Array(input.toSign))
      const { payload, verifyingKey, signature } = signed
      return { input, payload, verifyingKey, signature, key }
    }

    test('has a signature', async ({ page }) => {
      const out = await page.evaluate(scenario, { toSign })
      expect(out.signature).toBeDefined()
    })

    test('embeds the payload unchanged', async ({ page }) => {
      const out = await page.evaluate(scenario, { toSign })
      expect(Object.values(out.payload)).toStrictEqual(toSign)
    })
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
      return { payload: signed.payload }
    }, { toSign })

    expect(Object.values(out.payload)).toStrictEqual(toSign)
  })

  test('signature', async ({ page }) => {
    const out = await page.evaluate((input) => {
      const { SigningKey } = window.beehive
      const key = SigningKey.generate()
      const signed = key.trySign(new Uint8Array(input.toSign))
      return { signature: signed.signature }
    }, { toSign })

    expect(out.signature).toBeDefined()
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

  test.describe('idString', async () => {
    const scenario = () => {
      const { Beehive, SigningKey } = window.beehive
      const key = SigningKey.generate()
      const vKey = key.verifyingKey
      const beehive = new Beehive(key)
      return { idString: beehive.idString, vKey }
    }

    test('is >= 66 charecters', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.idString.length).toBeLessThanOrEqual(66)
    })

    test('is a hex string starting with 0x', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.idString).toMatch(/0x[0-9a-fA-F]+/)
    })
  })

  test.describe('generateGroup', async () => {
    const scenario = () => {
      const { Beehive, SigningKey } = window.beehive
      const beehive = new Beehive(SigningKey.generate())

      const group = beehive.generateGroup([])
      const { groupId, members } = group
      const canStr = members[0].can.toString()
      return { group, groupId, members, canStr }
    }

    test('makes a new group', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.group).toBeDefined()
    })

    test('the associated group has an groupId (is an actual group)', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.groupId).toBeDefined()
    })

    test('group has exacty one member', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.members).toHaveLength(1)
    })

    test('the sole group member is an admin', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.canStr).toStrictEqual('Admin')
    })
  })
})
