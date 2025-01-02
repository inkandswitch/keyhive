import { test, expect } from '@playwright/test';
import { URL } from './config';

test.beforeEach(async ({ page }) => {
  await page.goto(URL)
  await page.waitForFunction(() => !!window.beehive)
});

test.describe("Beehive", async () => {
  test('constructor', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, Signer } = window.beehive
      return { beehive: new Beehive(Signer.generateInMemory()) }
    })

    expect(out.beehive).toBeDefined()
  })

  test('id', async ({ page }) => {
    const out = await page.evaluate(() => {
      const { Beehive, Signer } = window.beehive
      const sk = Signer.generateInMemory()
      const vk = sk.verifyingKey
      const beehive = new Beehive(sk)
      return { id: beehive.id.bytes, vk }
    })

    expect(out.id).toStrictEqual(out.vk)
  })

  test.describe('idString', async () => {
    const scenario = () => {
      const { Beehive, Signer } = window.beehive
      const key = Signer.generateInMemory()
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
      const { Beehive, Signer } = window.beehive
      const beehive = new Beehive(Signer.generateInMemory())

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
})
