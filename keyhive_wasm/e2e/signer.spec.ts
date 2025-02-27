import { test, expect } from '@playwright/test';
import { URL } from './config';

const toSign = [1, 2, 3, 4, 5]

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.keyhive)
});

test.describe("Signer", async () => {
  test.describe("Generic", async () => {
    test.describe('constructor', async () => {
      const scenario = async () => {
        const { Signer } = window.keyhive
        const key = await new Signer()
        const variant = key.variant
        return { key, variant }
      }

      test('initializes successfully', async ({ page }) => {
        const out = await page.evaluate(scenario)
        expect(out.key).toBeDefined()
      })

      test('defaults to WebCrypto', async ({ page, browserName }) => {
        test.skip(browserName === 'chromium', 'waiting for Ed25519 to come out of feature flag');

        const out = await page.evaluate(scenario)
        expect(out.variant).toBe("WEB_CRYPTO")
      })

      test('falls back to an in-memory signer on Chrome (for now)', async ({ page, browserName }) => {
        test.skip(browserName !== 'chromium', 'waiting for Ed25519 to come out of feature flag');

        const out = await page.evaluate(scenario)
        expect(out.variant).toBe("MEMORY")
      })
    })
  })

  test.describe("Memory Signer", async () => {
    test.describe('constructor', async () => {
      const scenario = async () => {
        const { Signer } = window.keyhive
        const key = Signer.generateMemory()
        return { key }
      }

      test('initializes successfully', async ({ page }) => {
        const out = await page.evaluate(scenario)
        expect(out.key).toBeDefined()
      })
    })

    test.describe('verifyingKey', async () => {
      const scenario = async (input) => {
        const { Signer } = window.keyhive
        const key = Signer.generateMemory()
        return { input, key, vKey: key.verifyingKey }
      }

      test('has a verifying key', async ({ page }) => {
        const out = await page.evaluate(scenario, { toSign })
        expect(out.vKey).toBeDefined()
      })
    })

    test.describe('trySign', async () => {
      const scenario = async (input) => {
        const { Signer } = window.keyhive
        const key = Signer.generateMemory()
        const signed = await key.trySign(new Uint8Array(input.toSign))
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

  test.describe("WebCrypto", async () => {
    test.describe('constructor', async () => {
      const scenario = async () => {
        const { Signer } = window.keyhive
        const key = await Signer.generateWebCrypto()

        const keypair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
        const manualKey = await Signer.webCryptoSigner(keypair)

        return { key, manualKey }
      }

      test('initializes successfully', async ({ page, browserName }) => {
        test.skip(browserName === 'chromium', 'waiting for Ed25519 to come out of feature flag');

        const out = await page.evaluate(scenario)
        expect(out.key).toBeDefined()
      })

      test('loads from manual key', async ({ page, browserName }) => {
        test.skip(browserName === 'chromium', 'waiting for Ed25519 to come out of feature flag');

        const out = await page.evaluate(scenario)
        expect(out.manualKey).toBeDefined()
      })
    })

    test.describe('verifyingKey', async () => {
      const scenario = async (input) => {
        const { Signer } = window.keyhive
        const key = await Signer.generateWebCrypto()
        return { input, key, vKey: key.verifyingKey }
      }

      test('has a verifying key', async ({ page, browserName }) => {
        test.skip(browserName === 'chromium', 'waiting for Ed25519 to come out of feature flag');

        const out = await page.evaluate(scenario, { toSign })
        expect(out.vKey).toBeDefined()
      })
    })

    test.describe('trySign', async () => {
      const scenario = async (input) => {
        const { Signer } = window.keyhive
        const key = await Signer.generateWebCrypto()
        const signed = await key.trySign(new Uint8Array(input.toSign))
        const { payload, verifyingKey, signature } = signed
        return { input, payload, verifyingKey, signature, key }
      }

      test('has a signature', async ({ page, browserName }) => {
        test.skip(browserName === 'chromium', 'waiting for Ed25519 to come out of feature flag');

        const out = await page.evaluate(scenario, { toSign })
        expect(out.signature).toBeDefined()
      })

      test('embeds the payload unchanged', async ({ page, browserName }) => {
        test.skip(browserName === 'chromium', 'waiting for Ed25519 to come out of feature flag');

        const out = await page.evaluate(scenario, { toSign })
        expect(Object.values(out.payload)).toStrictEqual(toSign)
      })
    })
  })
})
