import { test, expect } from "@playwright/test";
import { URL } from "./config";

test.beforeEach(async ({ page }) => {
  await page.goto(URL);
  await page.waitForFunction(() => !!window.keyhive);
});

test("the id generateDocument returns resolves to that document", async ({
  page,
}) => {
  const out = await page.evaluate(async () => {
    const { Keyhive, Signer, ChangeId, CiphertextStore } = window.keyhive;

    const store = CiphertextStore.newInMemory();
    const kh = await Keyhive.init(await Signer.generate(), store, console.log);
    const changeId = new ChangeId(new Uint8Array([1, 2, 3]));

    const groupId = await kh.generateGroup([]);
    const docId = await kh.generateDocument(
      [groupId.toIdentifier()],
      changeId,
      [],
    );
    const doc = await kh.getDocument(docId);

    return { docId: docId.toString(), fetchedId: doc.docId.toString() };
  });

  expect(out.fetchedId).toBe(out.docId);
});
