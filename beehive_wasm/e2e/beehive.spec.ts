import { test, expect } from '@playwright/test';
import { URL } from './config';

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.beehive)
});

test.describe("Beehive", async () => {
  test('constructor', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, SigningKey } = window.beehive
      return { beehive: new Beehive(SigningKey.generate()) }
    })

    expect(out.beehive).toBeDefined()
  })

  test('id', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, SigningKey } = window.beehive
      const sk = SigningKey.generate()
      const vk = sk.verifyingKey
      const beehive = new Beehive(sk)
      return { id: beehive.id.bytes, vk }
    })

    expect(out.id).toStrictEqual(out.vk)
  })

  test.describe('idString', async () => {
    const scenario = () => {
      const { Beehive, SigningKey } = window.beehive
      const key = SigningKey.generate()
      const vKey = key.verifyingKey
      const beehive = new Beehive(key)
      return { idString: beehive.idString, vKey }
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
      const { Beehive, SigningKey } = window.beehive
      const beehive = new Beehive(SigningKey.generate())

      const group = beehive.generateGroup([])
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
      const { Beehive, SigningKey, Archive, ChangeRef } = window.beehive

      const bh = new Beehive(SigningKey.generate())
      const changeRef = new ChangeRef(new Uint8Array([1, 2, 3]));

      const g1 = bh.generateGroup([])
      const g2 = bh.generateGroup([g1.toPeer()])
      const d1 = bh.generateDoc([g2.toPeer()], changeRef, [])
      bh.generateGroup([d1.toPeer()])
      bh.generateGroup([g2.toPeer(), d1.toPeer()])

      const archive = bh.intoArchive()
      const archiveBytes = archive.toBytes()
      const archiveBytesIsUint8Array = archiveBytes instanceof Uint8Array
      const roundTrip = new Archive(archiveBytes).tryToBeehive()
      return { archive, archiveBytes, beehive: bh, roundTrip, archiveBytesIsUint8Array }
    }

    test('makes a new group', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.beehive).toBeDefined()
    })

    test('serializes to bytes', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.archiveBytesIsUint8Array).toBe(true)
    })

    test('round trip', async ({ page }) => {
      const out = await page.evaluate(scenario)
      expect(out.beehive.id).toBe(out.roundTrip.id)
    })
  })
})
