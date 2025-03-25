import { test, expect } from '@playwright/test';
import { URL } from './config';

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.keyhive)
});

test.describe("Document", async () => {
  test('constructor', async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { Keyhive, Signer, ChangeRef, CiphertextStore } = window.keyhive

      const store = CiphertextStore.newInMemory()
      const bh = await new Keyhive(await new Signer(), store, console.log)
      const changeRef = new ChangeRef(new Uint8Array([1, 2, 3]));

      const g = await bh.generateGroup([])
      const doc = await bh.generateDocument([g.toPeer()], changeRef, [])
      const docId = doc.id

      return { doc, docId }
    })

    expect(out.doc).toBeDefined()
    expect(out.docId).toBeDefined()
  })
})
