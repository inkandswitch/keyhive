import { test, expect } from "@playwright/test";
import { URL } from "./config";

test.beforeEach(async ({ page }) => {
  await page.goto(URL);
  await page.waitForFunction(() => !!window.keyhive);
});

const getTestContactCard = () => `
  {
    "Rotate": {
      "payload": {
        "old": [162,145,165,196,36,224,73,112,145,188,239,44,86,166,20,30,132,108,154,237,83,69,195,21,41,18,247,146,217,79,21,65],
        "new": [65,22,115,210,58,181,17,14,148,30,90,73,154,200,20,81,107,120,237,144,159,70,19,25,122,11,238,169,191,239,222,18]
      },
      "issuer": [89,148,210,47,52,105,242,130,40,253,172,205,17,39,98,47,171,251,25,33,19,205,115,101,160,144,209,139,13,6,168,3],
      "signature": [26,42,5,188,200,86,129,50,162,87,200,64,152,180,93,59,70,150,87,12,222,93,165,249,110,150,52,123,169,222,138,253,72,64,83,74,88,60,147,178,135,64,14,77,40,61,89,164,119,235,73,71,34,184,248,172,125,3,144,248,177,72,65,13]
    }
  }`;

test.describe("Keyhive", async () => {
  test("constructor", async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive;
      const store = CiphertextStore.newInMemory();
      return {
        keyhive: await Keyhive.init(
          await Signer.generate(),
          store,
          console.log,
        ),
      };
    });

    expect(out.keyhive).toBeDefined();
  });

  test("id", async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive;
      const sk = await Signer.generate();
      const vk = sk.verifyingKey;
      const store = CiphertextStore.newInMemory();
      const keyhive = await Keyhive.init(sk, store, console.log);
      return { id: keyhive.id.toBytes(), vk };
    });

    expect(out.id).toStrictEqual(out.vk);
  });

  test("idString is 0x followed by 64 hex digits", async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive;
      const key = await Signer.generate();
      const store = CiphertextStore.newInMemory();
      const keyhive = await Keyhive.init(key, store, console.log);
      return { idString: keyhive.idString };
    });

    expect(out.idString).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test("generateGroup returns the id of a group whose sole member is an admin", async ({
    page,
  }) => {
    const out = await page.evaluate(async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive;
      const store = CiphertextStore.newInMemory();
      const keyhive = await Keyhive.init(
        await Signer.generate(),
        store,
        (_) => {},
      );

      const groupId = await keyhive.generateGroup([]);
      const group = await keyhive.getGroup(groupId);
      const members = await group.members();
      return {
        groupId: groupId.toString(),
        fetchedGroupId: group.groupId.toString(),
        members,
        canStr: members[0].can.toString(),
      };
    });

    expect(out.fetchedGroupId).toBe(out.groupId);
    expect(out.members).toHaveLength(1);
    expect(out.canStr).toStrictEqual("Admin");
  });

  test("an archive serializes to bytes and round trips back to a keyhive", async ({
    page,
  }) => {
    const out = await page.evaluate(async (contactCardJson) => {
      const {
        Keyhive,
        Signer,
        Access,
        Archive,
        ChangeId,
        CiphertextStore,
        ContactCard,
        MemberedId,
      } = window.keyhive;
      const testContactCard = ContactCard.fromJson(contactCardJson);

      const signer = await Signer.generate();
      const ciphertextStore = CiphertextStore.newInMemory();
      const kh = await Keyhive.init(signer, ciphertextStore, () => {});
      const changeId = new ChangeId(new Uint8Array([1, 2, 3]));

      const g1Id = await kh.generateGroup([]);
      const arr = [g1Id.toIdentifier()];
      const g2Id = await kh.generateGroup(arr);
      const _ = await kh.generateGroup(arr);
      const d1Id = await kh.generateDocument(
        [g2Id.toIdentifier()],
        changeId,
        [],
      );
      await kh.generateGroup([d1Id.toIdentifier()]);
      await kh.generateGroup([g2Id.toIdentifier(), d1Id.toIdentifier()]);

      const individualId = await kh.receiveContactCard(testContactCard);
      const access = Access.tryFromString("edit");
      await kh.addMember(
        individualId.toIdentifier(),
        MemberedId.group(g2Id),
        access,
        [],
      );

      const archive = await kh.toArchive();
      const archiveBytes = archive.toBytes();
      const archiveBytesIsUint8Array = archiveBytes instanceof Uint8Array;
      const newStore = CiphertextStore.newInMemory();
      const archive2 = new Archive(archiveBytes);
      const roundTrip = await archive2.tryToKeyhive(newStore, signer);
      return {
        archive,
        archiveBytes,
        keyhive: kh,
        roundTrip,
        archiveBytesIsUint8Array,
      };
    }, getTestContactCard());

    expect(out.archiveBytesIsUint8Array).toBe(true);
    expect(out.keyhive.id).toBe(out.roundTrip.id);
  });

  test("receiveContactCard returns the id for the card", async ({ page }) => {
    const out = await page.evaluate(async (contactCardJson) => {
      const { Keyhive, Signer, CiphertextStore, ContactCard } = window.keyhive;
      const card = ContactCard.fromJson(contactCardJson);
      const kh = await Keyhive.init(
        await Signer.generate(),
        CiphertextStore.newInMemory(),
        () => {},
      );
      const individualId = await kh.receiveContactCard(card);
      return {
        received: individualId.toString(),
        expected: card.individualId.toString(),
      };
    }, getTestContactCard());

    expect(out.received).toBe(out.expected);
  });

  test("a listener records a prekey rotation", async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive;
      const events = [];
      const keyhive = await Keyhive.init(
        await Signer.generate(),
        CiphertextStore.newInMemory(),
        (event) => {
          events.push(event.variant);
        },
      );

      await keyhive.expandPrekeys();
      return { events };
    });

    expect(out.events).toHaveLength(1);
    expect(out.events[0]).toBe("PREKEYS_EXPANDED");
  });

  test("a listener that throws leaves the keyhive usable", async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive;
      const keyhive = await Keyhive.init(
        await Signer.generate(),
        CiphertextStore.newInMemory(),
        () => {
          throw new Error("listener failed");
        },
      );

      await keyhive.expandPrekeys();
      return { idString: keyhive.idString };
    });

    expect(out.idString).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test.describe("archive ingestion across keyhives", async () => {
    test("different keyhive can ingest archive with document", async ({
      page,
    }) => {
      const out = await page.evaluate(async () => {
        const { Keyhive, Signer, ChangeId, CiphertextStore, Archive } =
          window.keyhive;

        // Create first keyhive and a document
        const signer1 = await Signer.generate();
        const store1 = CiphertextStore.newInMemory();
        const kh1 = await Keyhive.init(signer1, store1, () => {});

        const changeId = new ChangeId(new Uint8Array([1, 2, 3]));
        await kh1.generateDocument([], changeId, []);

        const kh1Id = kh1.idString;

        // Export archive from first keyhive
        const archive = await kh1.toArchive();
        const archiveBytes = archive.toBytes();

        // Create second keyhive with different identity
        const signer2 = await Signer.generate();
        const store2 = CiphertextStore.newInMemory();
        const kh2 = await Keyhive.init(signer2, store2, () => {});
        const kh2Id = kh2.idString;

        // Try to ingest the archive into the second keyhive
        let ingestError = null;
        let ingestSuccess = false;
        try {
          const archiveToIngest = new Archive(archiveBytes);
          await kh2.ingestArchive(archiveToIngest);
          ingestSuccess = true;
        } catch (e) {
          ingestError = JSON.stringify(e, Object.getOwnPropertyNames(e));
        }

        return {
          kh1Id,
          kh2Id,
          ingestError,
          ingestSuccess,
        };
      });

      expect(out.kh1Id).not.toBe(out.kh2Id);
      expect(out.ingestSuccess).toBe(true);
      expect(out.ingestError).toBeNull();
    });

    test("can load archive after revoking a delegation", async ({ page }) => {
      const testContactCardJson = getTestContactCard();
      const out = await page.evaluate(async (contactCardJson) => {
        const {
          Keyhive,
          Signer,
          ChangeId,
          CiphertextStore,
          Archive,
          ContactCard,
          Access,
          MemberedId,
        } = window.keyhive;

        const testContactCard = ContactCard.fromJson(contactCardJson);

        const signer = await Signer.generate();
        const store = CiphertextStore.newInMemory();
        const kh = await Keyhive.init(signer, store, () => {});
        const changeId = new ChangeId(new Uint8Array([1, 2, 3]));
        const docId = await kh.generateDocument([], changeId, []);

        // Delegate to an individual
        const individualId = await kh.receiveContactCard(testContactCard);
        const member = individualId.toIdentifier();
        const membered = MemberedId.document(docId);
        const access = Access.tryFromString("edit");
        await kh.addMember(member, membered, access, []);

        // Revoke that individual
        await kh.revokeMember(member, true, membered);

        // Create an archive
        const archive = await kh.toArchive();
        const archiveBytes = archive.toBytes();

        // Try to load the archive in a fresh keyhive
        let loadError = null;
        let loadSuccess = false;
        try {
          const freshStore = CiphertextStore.newInMemory();
          const archiveToLoad = new Archive(archiveBytes);
          const freshKh = await archiveToLoad.tryToKeyhive(freshStore, signer);
          loadSuccess = true;
        } catch (e) {
          loadError = {
            message: e.message,
            name: e.name,
            toString: e.toString(),
          };
        }

        return {
          loadSuccess,
          loadError,
        };
      }, testContactCardJson);

      if (!out.loadSuccess) {
        console.log(
          "Load failed with error:",
          JSON.stringify(out.loadError, null, 2),
        );
      }

      expect(out.loadSuccess).toBe(true);
      expect(out.loadError).toBeNull();
    });
  });
});
