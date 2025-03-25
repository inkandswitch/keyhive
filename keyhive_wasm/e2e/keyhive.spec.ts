import { test, expect } from '@playwright/test';
import { URL } from './config';

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.keyhive)
});

test.describe("Keyhive", async () => {
  test('constructor', async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive
      const store = CiphertextStore.newInMemory()
      return { keyhive: await new Keyhive(await new Signer(), store, console.log) }
    })

    expect(out.keyhive).toBeDefined()
  })

  test('id', async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive
      const sk = await new Signer()
      const vk = sk.verifyingKey
      const store = CiphertextStore.newInMemory()
      const keyhive = await new Keyhive(sk, store, console.log)
      return { id: keyhive.id.bytes, vk }
    })

    expect(out.id).toStrictEqual(out.vk)
  })

  test.describe('idString', async () => {
    const scenario = async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive
      const key = await new Signer()
      const vKey = key.verifyingKey
      const store = CiphertextStore.newInMemory()
      const keyhive = await new Keyhive(key, store, console.log)
      return { idString: keyhive.idString, vKey }
    }

    test('is >= 66 charecters', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.idString.length).toBeLessThanOrEqual(66)
    })

    test('is a hex string starting with 0x', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.idString).toMatch(/0x[0-9a-fA-F]+/)
    })
  })

  test.describe('generateGroup', async () => {
    const scenario = async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive
      const store = CiphertextStore.newInMemory()
      const keyhive = await new Keyhive(await new Signer(), store, (_) => {})

      const group = await keyhive.generateGroup([])
      const { groupId, members } = group
      const canStr = members[0].can.toString()
      return { group, groupId, members, canStr }
    }

    test('makes a new group', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.group).toBeDefined()
    })

    test('the associated group has an groupId (is an actual group)', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.groupId).toBeDefined()
    })

    test('group has exacty one member', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.members).toHaveLength(1)
    })

    test('the sole group member is an admin', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.canStr).toStrictEqual('Admin')
    })
  })

  test.describe('archive', async () => {
    const scenario = async () => {
      const { Keyhive, Signer, Archive, ChangeRef, CiphertextStore } = window.keyhive

      const signer = await new Signer()
      const secondSigner = signer.clone()
      const ciphertextStore = CiphertextStore.newInMemory();
      const kh = await new Keyhive(signer, ciphertextStore, () => {})
      const changeRef = new ChangeRef(new Uint8Array([1, 2, 3]));

      const g1 = await kh.generateGroup([])
      const g2 = await kh.generateGroup([g1.toPeer()])
      const d1 = await kh.generateDocument([g2.toPeer()], changeRef, [])
      await kh.generateGroup([d1.toPeer()])
      await kh.generateGroup([g2.toPeer(), d1.toPeer()])

      const archive = kh.intoArchive()
      const archiveBytes = archive.toBytes()
      const archiveBytesIsUint8Array = archiveBytes instanceof Uint8Array
      const newStore = CiphertextStore.newInMemory()
      const roundTrip = new Archive(archiveBytes).tryToKeyhive(newStore, secondSigner)
      return { archive, archiveBytes, keyhive: kh, roundTrip, archiveBytesIsUint8Array }
    }

    test('makes a new group', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.keyhive).toBeDefined()
    })

    test('serializes to bytes', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.archiveBytesIsUint8Array).toBe(true)
    })

    test('round trip', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.keyhive.id).toBe(out.roundTrip.id)
    })
  })

  test.describe('event listener', async () => {
    const scenario = async () => {
      const { Keyhive, Signer, CiphertextStore } = window.keyhive
      const events = [];
      const ciphertextStore = CiphertextStore.newInMemory();
      const keyhive = await new Keyhive(await new Signer(), ciphertextStore, (event) => {
        console.log(event);
        events.push(event.variant);
      })

      await keyhive.expandPrekeys()
      return { events }
    }

    test('records a prekey rotation', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.events).toHaveLength(1)
      expect(out.events[0]).toBe("PREKEYS_EXPANDED")
    })
  })
})
