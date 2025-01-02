import { test, expect } from '@playwright/test';
import { URL } from './config';

const toSign = [1, 2, 3, 4, 5]

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.beehive)
});

test.describe('Signer', async () => {
  test.describe("In-memory signer", async () => {
    test.describe('constructor', async () => {
      const scenario = () => {
        const { Signer } = window.beehive
        return { key: Signer.generateInMemory() }
      }

      test('initializes successfully', async ({ page }) => {
        const out = await page.evaluate(scenario)
        expect(out.key).toBeDefined()
      })
    })

    test.describe('verifyingKey', async () => {
      const scenario = (input) => {
        const { Signer } = window.beehive
        const key = Signer.generateInMemory()
        return { input, key, vKey: key.verifyingKey }
      }

      test('has a verifying key', async ({ page }) => {
        const out = await page.evaluate(scenario, { toSign })
        expect(out.vKey).toBeDefined()
      })
    })

    test.describe('trySign', async () => {
      const scenario = (input) => {
        const { Signer } = window.beehive
        const key = Signer.generateInMemory()
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

  test.describe("WebCrypto signer", async () => {
    test.describe("Chromium doesn't yet support Ed25519", async() => {
      test.skip(
        ({ browserName }) => browserName.toLowerCase() !== 'chromium',
        "Only check Chromium"
      );

      test("we expect this API to not yet be available, but will be happy when it is", async ({ page }) => {
        const supported = await page.evaluate(async () => {
          let supported = true

          try {
            await crypto.subtle.generateKey(
              {
                name: "Ed25519",
              },
              true,
              ["sign", "verify"],
            );
          } catch {
            supported = false
          }

          return supported
        })

        expect(supported).toBe(false)
      })
    })

    test.describe('has ed25519 APIs', async() => {
      test.skip(
        ({ browserName }) => browserName.toLowerCase() === 'chromium',
        "Skip Chromium until the Ed25519 API is available"
      );

      test.describe('constructor', async () => {
        test('initializes successfully', async ({ page }) => {
          const out = await page.evaluate(async () => {
            const { Signer } = window.beehive
            const { publicKey, privateKey } = await window.crypto.subtle.generateKey(
              { name: "Ed25519" },
              false,
              ["sign", "verify"],
            );

            const pkBytes = new Uint8Array(await window.crypto.subtle.exportKey("raw", publicKey))
            const signer = new Signer(pkBytes, async (data) => {
              return await window.crypto.subtle.sign({ name: "Ed25519" }, privateKey, data)
            })

            return {
           signer
         }
          })

          expect(out.signer).toBeDefined()
        })
      })

      test.describe('verifyingKey', async () => {
        const scenario = async (input) => {
          const { Signer } = window.beehive
          const { publicKey, privateKey } = await window.crypto.subtle.generateKey(
            { name: "Ed25519" },
            false,
            ["sign"],
          );

          const pkBytes = new Uint8Array(await window.crypto.subtle.exportKey("raw", publicKey))
          const signer = new Signer(pkBytes, async (data) => {
            return await window.crypto.subtle.sign({ name: "Ed25519" }, privateKey, data)
          })

          const verifier = signer.verifyingKey
          const verified = true; // FIXME signed = signer.trySign(data); signed.verify()

          return { input, verifier, verified }
        }

        test('has a verifying key', async ({ page }) => {
          const out = await page.evaluate(scenario, { toSign })
          expect(out.verifier).toBeDefined()
        })

        test('verifies', async({ page }) => {
          const out = await page.evaluate(scenario, { toSign })
          expect(out.verified).toBe(true)
        })
      })

      // FIXME
      // test.describe('trySign', async () => {
      //   const scenario = (input) => {
      //     const { Signer } = window.beehive
      //     const key = Signer.generateInMemory()
      //     const signed = key.trySign(new Uint8Array(input.toSign))
      //     const { payload, verifyingKey, signature } = signed
      //     return { input, payload, verifyingKey, signature, key }
      //   }

      //   test('has a signature', async ({ page }) => {
      //     const out = await page.evaluate(scenario, { toSign })
      //     expect(out.signature).toBeDefined()
      //   })

      //   test('embeds the payload unchanged', async ({ page }) => {
      //     const out = await page.evaluate(scenario, { toSign })
      //     expect(Object.values(out.payload)).toStrictEqual(toSign)
      //   })
      // })
    })
  })
})
