import { test, expect } from '@playwright/test';

const URL = "http://localhost:6891/";
const foo = async (page) => {
  const found = await page.evaluate(() => {
    return window.beehive
  })
  return found
}

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.beehive)
});

test.describe("SigningKey", () => {
  test('constructor', async({ page }) => {
    const { SigningKey } = await foo(page)

    const bytes = new Uint8Array(32) // Oops all zeroes!
    const observed = new SigningKey(bytes)

    expect(observed).toBeDefined()
  })
})

// test.describe("JsBeehive", () => {
//   test('constructor', async({ page }) => {
//     const { JsBeehive, SigningKey } = await foo(page);
//
//     const bar = new Uint8Array(32) // Oops all zeroes!
//     const signer = new SigningKey(bar)
//     const observed = new JsBeehive(signer)
//
//     expect(observed).toBeDefined()
//   })
// })
