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

test("the leaf secret forcePcsUpdate returns imports with importPrekeySecrets", async ({
  page,
}) => {
  const out = await page.evaluate(async () => {
    const { Keyhive, Signer, ChangeId, CiphertextStore } = window.keyhive;
    const kh = await Keyhive.init(
      await Signer.generate(),
      CiphertextStore.newInMemory(),
      () => {},
    );
    const docId = await kh.generateDocument(
      [],
      new ChangeId(new Uint8Array([1, 2, 3])),
      [],
    );
    const leafSecret = await kh.forcePcsUpdate(docId);
    try {
      await kh.importPrekeySecrets(leafSecret);
      return { imported: true };
    } catch (e) {
      return { imported: false, error: String(e) };
    }
  });

  expect(out).toEqual({ imported: true });
});

test("a document lists its members directly and transitively", async ({
  page,
}) => {
  const out = await page.evaluate(async () => {
    const { Keyhive, Signer, ChangeId, CiphertextStore, MemberedId, Power } =
      window.keyhive;
    const newKeyhive = async () =>
      Keyhive.init(await Signer.generate(), CiphertextStore.newInMemory(), (_) => {});
    const alice = await newKeyhive();
    const bob = await newKeyhive();
    const bobId = (await alice.receiveContactCard(await bob.contactCard())).toIdentifier();

    const groupId = await alice.generateGroup([]);
    await alice.addMember(bobId, MemberedId.group(groupId), Power.read());
    const docId = await alice.generateDocument(
      [],
      new ChangeId(new Uint8Array([1, 2, 3])),
      [],
    );
    await alice.addMember(groupId.toIdentifier(), MemberedId.document(docId), Power.edit());

    const doc = await alice.getDocument(docId);
    const direct = (await doc.members()).map((c) => [c.who.toString(), c.can.toString()]);
    const transitive = (await doc.transitiveMembers()).map((m) => m.who.id.toString());
    return {
      direct,
      transitive,
      alice: alice.id.toIdentifier().toString(),
      bob: bobId.toString(),
      group: groupId.toString(),
    };
  });

  expect(out.direct).toContainEqual([out.group, "Edit"]);
  expect(out.direct).not.toContainEqual(expect.arrayContaining([out.bob]));
  expect(out.transitive).toContain(out.bob);
  expect(out.transitive).toContain(out.alice);
});
