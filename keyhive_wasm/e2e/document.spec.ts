import { test, expect } from '@playwright/test';
import { URL } from './config';

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.keyhive)
});

test.describe("Document", async () => {
  test('constructor', async ({ page }) => {
    const out = await page.evaluate(() => {
        const { Keyhive, SigningKey, ChangeRef } = window.keyhive

        const bh = new Keyhive(SigningKey.generate())
        const changeRef = new ChangeRef(new Uint8Array([1, 2, 3]));

        const g = bh.generateGroup([]).toPeer()
        const doc = bh.generateDocument([g], changeRef, [])
        const docId = doc.id

        return { doc, docId }
    })

    expect(out.doc).toBeDefined()
    expect(out.docId).toBeDefined()
  })
})
