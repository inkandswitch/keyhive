import { test, expect } from '@playwright/test';
import { URL } from './config';

const toSign = [1, 2, 3, 4, 5]

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.keyhive)
});

test.describe("Signed", async () => {
  test('verify', async ({ page }) => {
    const out = await page.evaluate(async (input) => {
      const { Signer } = window.keyhive
      const key = await new Signer()
      const signed = await key.trySign(new Uint8Array(input.toSign))
      const { payload, verifyingKey, signature } = signed
      const verified = signed.verify()
      return { input, payload, verifyingKey, signature, verified, key }
    }, { toSign })

    expect(out.verified).toBe(true)
  })

  test('payload', async ({ page }) => {
    const out = await page.evaluate(async (input) => {
      const { Signer } = window.keyhive
      const key = await new Signer()
      const signed = await key.trySign(new Uint8Array(input.toSign))
      return { payload: signed.payload }
    }, { toSign })

    expect(Object.values(out.payload)).toStrictEqual(toSign)
  })

  test('signature', async ({ page }) => {
    const out = await page.evaluate(async (input) => {
      const { Signer } = window.keyhive
      const key = await new Signer()
      const signed = await key.trySign(new Uint8Array(input.toSign))
      return { signature: signed.signature }
    }, { toSign })

    expect(out.signature).toBeDefined()
  })
})
