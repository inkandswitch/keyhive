import { test, expect } from '@playwright/test';
import { URL } from './config';

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.beehive)
});

test.describe("Document", async () => {
  test('constructor', async ({ page }) => {
    const out = await page.evaluate(() => {
        const { Beehive, SigningKey, ChangeRef } = window.beehive

        const bh = new Beehive(SigningKey.generate())
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
