import { test, expect } from "@playwright/test";
import { URL } from "./config";

test.beforeEach(async ({ page }) => {
  await page.goto(URL);
  await page.waitForFunction(() => !!window.keyhive);
});

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
      return { id: keyhive.id.bytes, vk };
    });

    expect(out.id).toStrictEqual(out.vk);
  });

  test.describe("idString", async () => {
    const scenario = async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive;
      const key = await Signer.generate();
      const vKey = key.verifyingKey;
      const store = CiphertextStore.newInMemory();
      const keyhive = await Keyhive.init(key, store, console.log);
      return { idString: keyhive.idString, vKey };
    };

    test("is >= 66 charecters", async ({ page }) => {
      const out = await page.evaluate(scenario);
      expect(out.idString.length).toBeLessThanOrEqual(66);
    });

    test("is a hex string starting with 0x", async ({ page }) => {
      const out = await page.evaluate(scenario);
      expect(out.idString).toMatch(/0x[0-9a-fA-F]+/);
    });
  });

  test.describe("generateGroup", async () => {
    const scenario = async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive;
      const store = CiphertextStore.newInMemory();
      const keyhive = await Keyhive.init(
        await Signer.generate(),
        store,
        (_) => {},
      );

      const group = await keyhive.generateGroup([]);
      const { groupId, members } = group;
      const canStr = members[0].can.toString();
      return { group, groupId, members, canStr };
    };

    test("makes a new group", async ({ page }) => {
      const out = await page.evaluate(scenario);
      expect(out.group).toBeDefined();
    });

    test("the associated group has an groupId (is an actual group)", async ({
      page,
    }) => {
      const out = await page.evaluate(scenario);
      expect(out.groupId).toBeDefined();
    });

    test("group has exacty one member", async ({ page }) => {
      const out = await page.evaluate(scenario);
      expect(out.members).toHaveLength(1);
    });

    test("the sole group member is an admin", async ({ page }) => {
      const out = await page.evaluate(scenario);
      expect(out.canStr).toStrictEqual("Admin");
    });
  });

  test.describe("archive", async () => {
    const scenario = async () => {
      const { Keyhive, Signer, Access, Archive, ChangeRef, CiphertextStore, ContactCard, Individual } =
        window.keyhive
      const testContactCard = ContactCard.fromJson(`{"Rotate":{"payload":{"old":[162,145,165,196,36,224,73,112,145,188,239,44,86,166,20,30,132,108,154,237,83,69,195,21,41,18,247,146,217,79,21,65],"new":[65,22,115,210,58,181,17,14,148,30,90,73,154,200,20,81,107,120,237,144,159,70,19,25,122,11,238,169,191,239,222,18]},"issuer":[89,148,210,47,52,105,242,130,40,253,172,205,17,39,98,47,171,251,25,33,19,205,115,101,160,144,209,139,13,6,168,3],"signature":[26,42,5,188,200,86,129,50,162,87,200,64,152,180,93,59,70,150,87,12,222,93,165,249,110,150,52,123,169,222,138,253,72,64,83,74,88,60,147,178,135,64,14,77,40,61,89,164,119,235,73,71,34,184,248,172,125,3,144,248,177,72,65,13]}}`)

      const signer = await Signer.generate();
      const secondSigner = signer.clone();
      const ciphertextStore = CiphertextStore.newInMemory();
      const kh = await Keyhive.init(signer, ciphertextStore, () => {});
      const changeRef = new ChangeRef(new Uint8Array([1, 2, 3]));

      const g1 = await kh.generateGroup([]);
      const g2 = await kh.generateGroup([g1.toPeer()]);
      const d1 = await kh.generateDocument([g2.toPeer()], changeRef, []);
      await kh.generateGroup([d1.toPeer()]);
      await kh.generateGroup([g2.toPeer(), d1.toPeer()]);

      const individual = kh.receiveContactCard(testContactCard)
      const access = Access.tryFromString("write");
      kh.addMember(individual.toAgent(), g2.toMembered(), access, []);

      const archive = kh.intoArchive();
      const archiveBytes = archive.toBytes();
      const archiveBytesIsUint8Array = archiveBytes instanceof Uint8Array;
      const newStore = CiphertextStore.newInMemory();
      const roundTrip = new Archive(archiveBytes).tryToKeyhive(
        newStore,
        secondSigner
      );
      return {
        archive,
        archiveBytes,
        keyhive: kh,
        roundTrip,
        archiveBytesIsUint8Array
      };
    }

    test("makes a new group", async ({ page }) => {
      const out = await page.evaluate(scenario);
      expect(out.keyhive).toBeDefined();
    });

    test("serializes to bytes", async ({ page }) => {
      const out = await page.evaluate(scenario);
      expect(out.archiveBytesIsUint8Array).toBe(true);
    });

    test("round trip", async ({ page }) => {
      const out = await page.evaluate(scenario);
      expect(out.keyhive.id).toBe(out.roundTrip.id);
    });
  });

  test.describe("event listener", async () => {
    const scenario = async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive;
      const events = [];
      const ciphertextStore = CiphertextStore.newInMemory();
      const keyhive = await Keyhive.init(
        await Signer.generate(),
        ciphertextStore,
        (event) => {
          console.log(event);
          events.push(event.variant);
        },
      );

      await keyhive.expandPrekeys();
      return { events };
    };

    test("records a prekey rotation", async ({ page }) => {
      const out = await page.evaluate(scenario);
      expect(out.events).toHaveLength(1);
      expect(out.events[0]).toBe("PREKEYS_EXPANDED");
    });
  });
});
