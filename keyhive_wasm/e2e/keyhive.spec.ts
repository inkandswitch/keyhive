import { test, expect } from "@playwright/test";
import { URL } from "./config";

test.beforeEach(async ({ page }) => {
  await page.goto(URL);
  await page.waitForFunction(() => !!window.keyhive);
});

// A rotation signed by the Ed25519 key with secret bytes [7; 32], as its KH
// frame: "KH" ‖ 'T' ‖ version ‖ issuer ‖ payload length ‖ old ‖ new ‖ signature.
const issuer = [234,74,108,99,226,156,82,10,190,245,80,123,19,46,197,249,149,71,118,174,190,190,123,146,66,30,234,105,20,70,210,44];
const oldAndNew = [65,72,98,244,93,220,223,84,102,12,226,149,30,120,221,84,15,181,6,15,254,54,104,135,40,99,37,27,176,207,119,88,84,127,25,212,176,19,41,32,72,136,105,120,233,7,111,204,55,87,25,251,66,71,167,254,158,220,219,86,10,38,186,104];
const signature = [139,75,216,43,101,202,118,100,70,50,115,75,239,211,175,199,24,1,208,203,124,29,221,64,231,113,90,162,203,128,148,206,9,105,158,217,214,150,20,220,90,234,106,184,150,62,147,194,177,42,111,96,176,110,214,254,225,173,132,221,17,34,66,9];
const testContactCard = [0x4b, 0x48, 0x54, 0x00, ...issuer, oldAndNew.length, ...oldAndNew, ...signature];

const getTestContactCard = () => testContactCard;

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

  test("a principal's string is its whole identifier", async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive;
      const kh = await Keyhive.init(
        await Signer.generate(),
        CiphertextStore.newInMemory(),
        () => {},
      );
      const groupId = await kh.generateGroup([]);
      const principal = await kh.getPrincipal(groupId.toIdentifier());
      return {
        principal: principal.toString(),
        identifier: groupId.toIdentifier().toString(),
      };
    });

    expect(out.principal).toMatch(/^0x[0-9a-f]{64}$/);
    expect(out.principal).toBe(out.identifier);
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
    const out = await page.evaluate(async (contactCardBytes) => {
      const {
        Keyhive,
        Signer,
        Power,
        Archive,
        ChangeId,
        CiphertextStore,
        ContactCard,
        MemberedId,
      } = window.keyhive;
      const testContactCard = ContactCard.fromBytes(new Uint8Array(contactCardBytes));

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
      const access = Power.tryFromString("edit");
      await kh.addMember(
        individualId.toIdentifier(),
        MemberedId.group(g2Id),
        access);

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

  test("a contact card whose signature does not verify is refused", async ({ page }) => {
    const forged = [...testContactCard];
    forged[forged.length - signature.length] ^= 1;
    const out = await page.evaluate(async (bytes) => {
      const { ContactCard } = window.keyhive;
      try {
        ContactCard.fromBytes(new Uint8Array(bytes));
        return { error: null };
      } catch (e) {
        return { error: String(e) };
      }
    }, forged);

    expect(out.error).toContain("signature does not verify");
  });

  test("receiveContactCard returns the id for the card", async ({ page }) => {
    const out = await page.evaluate(async (contactCardBytes) => {
      const { Keyhive, Signer, CiphertextStore, ContactCard } = window.keyhive;
      const card = ContactCard.fromBytes(new Uint8Array(contactCardBytes));
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

  test("addMember returns the delegation and revokeMember its revocation", async ({
    page,
  }) => {
    const out = await page.evaluate(async (contactCardBytes) => {
      const { Keyhive, Signer, CiphertextStore, ContactCard, MemberedId, Power } =
        window.keyhive;
      const kh = await Keyhive.init(
        await Signer.generate(),
        CiphertextStore.newInMemory(),
        (_) => {},
      );
      const groupId = await kh.generateGroup([]);
      const member = (
        await kh.receiveContactCard(ContactCard.fromBytes(new Uint8Array(contactCardBytes)))
      ).toIdentifier();

      const dlg = await kh.addMember(
        member,
        MemberedId.group(groupId),
        Power.tryFromString("edit"));
      const revs = await kh.revokeMember(member, false, MemberedId.group(groupId));
      return {
        verified: dlg.verify(),
        can: dlg.delegation.can.toString(),
        delegate: dlg.delegation.delegate.toString(),
        subject: dlg.subjectId.toString(),
        member: member.toString(),
        group: groupId.toString(),
        dlgId: Array.from(dlg.id),
        revCount: revs.length,
        revVerified: revs.every((r) => r.verify()),
        revoked: revs.map((r) => Array.from(r.revocation.revoked)),
      };
    }, getTestContactCard());

    expect(out.verified).toBe(true);
    expect(out.can).toBe("Edit");
    expect(out.delegate).toBe(out.member);
    expect(out.subject).toBe(out.group);
    expect(out.revCount).toBe(1);
    expect(out.revVerified).toBe(true);
    expect(out.revoked).toStrictEqual([out.dlgId]);
  });

  test("a listener sees a membership change as a signed delegation", async ({
    page,
  }) => {
    const out = await page.evaluate(async (contactCardBytes) => {
      const { Keyhive, Signer, CiphertextStore, ContactCard, MemberedId, Power } =
        window.keyhive;
      const delegations = [];
      const kh = await Keyhive.init(
        await Signer.generate(),
        CiphertextStore.newInMemory(),
        (event) => {
          const dlg = event.asSignedDelegation();
          if (dlg) {
            delegations.push(dlg.delegation.can.toString());
          }
        },
      );
      const groupId = await kh.generateGroup([]);
      const member = (
        await kh.receiveContactCard(ContactCard.fromBytes(new Uint8Array(contactCardBytes)))
      ).toIdentifier();
      await kh.addMember(
        member,
        MemberedId.group(groupId),
        Power.tryFromString("read"));
      return { delegations };
    }, getTestContactCard());

    expect(out.delegations).toStrictEqual(["Admin", "Read"]);
  });

  test("a revocation retains the heads the application set", async ({ page }) => {
    const out = await page.evaluate(async (contactCardBytes) => {
      const { ChangeId, Keyhive, Signer, CiphertextStore, ContactCard, MemberedId, Power } =
        window.keyhive;
      const kh = await Keyhive.init(
        await Signer.generate(),
        CiphertextStore.newInMemory(),
        (_) => {},
      );
      const docId = await kh.generateDocument(
        [],
        new ChangeId(new Uint8Array(32).fill(7)),
        [],
      );
      const otherId = await kh.generateDocument([], new ChangeId(new Uint8Array(32).fill(8)), []);
      const member = (
        await kh.receiveContactCard(ContactCard.fromBytes(new Uint8Array(contactCardBytes)))
      ).toIdentifier();

      const latest = new Uint8Array(32).fill(9);
      await kh.setContentHeads(docId, [new ChangeId(latest)]);

      await kh.addMember(member, MemberedId.document(docId), Power.read());
      const [rev] = await kh.revokeMember(member, false, MemberedId.document(docId));
      return {
        retained: rev.revocation.retained(docId)?.map((h) => Array.from(h.toBytes())),
        other: rev.revocation.retained(otherId),
        latest: Array.from(latest),
      };
    }, getTestContactCard());

    expect(out.retained).toStrictEqual([out.latest]);
    expect(out.other).toBeUndefined();
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

  test("encrypted content is KHE bytes, bound to its document", async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { ChangeId, Keyhive, Signer, CiphertextStore, Encrypted } = window.keyhive;
      const kh = await Keyhive.init(
        await Signer.generate(),
        CiphertextStore.newInMemory(),
        (_) => {},
      );
      const docId = await kh.generateDocument([], new ChangeId(new Uint8Array(32).fill(1)), []);
      const otherId = await kh.generateDocument([], new ChangeId(new Uint8Array(32).fill(2)), []);
      const keyed = await kh.tryEncryptKeyed(
        docId,
        new ChangeId(new Uint8Array(32).fill(3)),
        [],
        new Uint8Array([1, 2, 3]),
      );
      const bytes = keyed.encryptedContent().toBytes();
      const read = Encrypted.fromBytes(bytes);
      let otherDocRefused = false;
      try {
        read.decryptWithKey(keyed.applicationSecret, otherId);
      } catch {
        otherDocRefused = true;
      }
      return {
        header: Array.from(bytes.slice(0, 4)),
        plaintext: Array.from(read.decryptWithKey(keyed.applicationSecret, docId)),
        otherDocRefused,
      };
    });

    expect(out.header).toStrictEqual([0x4b, 0x48, 0x45, 0x00]); // "KHE", version 0
    expect(out.plaintext).toStrictEqual([1, 2, 3]);
    expect(out.otherDocRefused).toBe(true);
  });

  test("a causal decryption reads the ancestors an async load returns", async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { ChangeId, Keyhive, Signer, CiphertextStore } = window.keyhive;
      const kh = await Keyhive.init(
        await Signer.generate(),
        CiphertextStore.newInMemory(),
        (_) => {},
      );
      const docId = await kh.generateDocument([], new ChangeId(new Uint8Array([0])), []);
      const parentRef = new ChangeId(new Uint8Array([1]));
      const parent = await kh.tryEncrypt(docId, parentRef, [], new Uint8Array([1]));
      const child = await kh.tryEncrypt(
        docId,
        new ChangeId(new Uint8Array([2])),
        [parentRef],
        new Uint8Array([2]),
      );
      const parentBytes = parent.encryptedContent().toBytes();
      const read = await kh.tryCausalDecrypt(
        docId,
        child.encryptedContent(),
        async (id) => (id.toBytes()[0] === 1 ? parentBytes : undefined),
      );
      return read.complete().map((block) => Array.from(block.content()));
    });

    expect(out).toStrictEqual([[2], [1]]);
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
      const testContactCardBytes = getTestContactCard();
      const out = await page.evaluate(async (contactCardBytes) => {
        const {
          Keyhive,
          Signer,
          ChangeId,
          CiphertextStore,
          Archive,
          ContactCard,
          Power,
          MemberedId,
        } = window.keyhive;

        const testContactCard = ContactCard.fromBytes(new Uint8Array(contactCardBytes));

        const signer = await Signer.generate();
        const store = CiphertextStore.newInMemory();
        const kh = await Keyhive.init(signer, store, () => {});
        const changeId = new ChangeId(new Uint8Array([1, 2, 3]));
        const docId = await kh.generateDocument([], changeId, []);

        // Delegate to an individual
        const individualId = await kh.receiveContactCard(testContactCard);
        const member = individualId.toIdentifier();
        const membered = MemberedId.document(docId);
        const access = Power.tryFromString("edit");
        await kh.addMember(member, membered, access);

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
      }, testContactCardBytes);

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
