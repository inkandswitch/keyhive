import { test, expect } from '@playwright/test';
import { URL } from './config';

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.keyhive)
});

test.describe("Keyhive", async () => {
  test('constructor', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Keyhive, SigningKey } = window.keyhive
      return { keyhive: new Keyhive(SigningKey.generate(), console.log) }
    })

    expect(out.keyhive).toBeDefined()
  })

  test('id', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Keyhive, SigningKey } = window.keyhive
      const sk = SigningKey.generate()
      const vk = sk.verifyingKey
      const keyhive = new Keyhive(sk, console.log)
      return { id: keyhive.id.bytes, vk }
    })

    expect(out.id).toStrictEqual(out.vk)
  })

  test.describe('idString', async () => {
    const scenario = () => {
      const { Keyhive, SigningKey } = window.keyhive
      const key = SigningKey.generate()
      const vKey = key.verifyingKey
      const keyhive = new Keyhive(key, console.log)
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
    const scenario = () => {
      const { Keyhive, SigningKey } = window.keyhive
      const keyhive = new Keyhive(SigningKey.generate(), (_) => {})

      const group = keyhive.generateGroup([])
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
    const scenario = () => {
      const { Keyhive, SigningKey, Archive, ChangeRef } = window.keyhive

      const bh = new Keyhive(SigningKey.generate())
      const changeRef = new ChangeRef(new Uint8Array([1, 2, 3]));

      const g1 = bh.generateGroup([])
      const g2 = bh.generateGroup([g1.toPeer()])
      const d1 = bh.generateDocument([g2.toPeer()], changeRef, [])
      bh.generateGroup([d1.toPeer()])
      bh.generateGroup([g2.toPeer(), d1.toPeer()])

      const archive = bh.intoArchive()
      const archiveBytes = archive.toBytes()
      const archiveBytesIsUint8Array = archiveBytes instanceof Uint8Array
      const roundTrip = new Archive(archiveBytes).tryToKeyhive()
      return { archive, archiveBytes, keyhive: bh, roundTrip, archiveBytesIsUint8Array }
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
    const scenario = () => {
      const { Keyhive, SigningKey } = window.keyhive
      const events = [];
      const keyhive = new Keyhive(SigningKey.generate(), (event) => {
        console.log(event);
        events.push(event.variant);
      })

      keyhive.expandPrekeys()
      return { events }
    }

    test('records a prekey rotation', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.events).toHaveLength(1)
      expect(out.events[0]).toBe("PREKEYS_EXPANDED")
    })
  })
})
