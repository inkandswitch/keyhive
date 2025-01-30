import { test, expect } from '@playwright/test';
import { URL } from './config';

const toSign = [1, 2, 3, 4, 5]

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.keyhive)
});

test.describe("SigningKey", async () => {
  test.describe('constructor', async () => {
    const scenario = () => {
      const { SigningKey } = window.keyhive
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
      const { SigningKey } = window.keyhive
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
      const { SigningKey } = window.keyhive
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
