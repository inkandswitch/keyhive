import { test, expect } from "@playwright/test";
import { URL } from "./config";

const toSign = [1, 2, 3, 4, 5];

test.beforeEach(async ({ page }) => {
  await page.goto(URL);
  await page.waitForFunction(() => !!window.keyhive);
});

test.describe("Signed", async () => {
  test("verify", async ({ page }) => {
    const out = await page.evaluate(
      async (input) => {
        const { Signer } = window.keyhive;
        const key = await Signer.generate();
        const signed = await key.trySign(new Uint8Array(input.toSign));
        return { verified: signed.verify() };
      },
      { toSign },
    );

    expect(out.verified).toBe(true);
  });

  test("payload", async ({ page }) => {
    const out = await page.evaluate(
      async (input) => {
        const { Signer } = window.keyhive;
        const key = await Signer.generate();
        const signed = await key.trySign(new Uint8Array(input.toSign));
        return { payload: signed.payload() };
      },
      { toSign },
    );

    expect(Object.values(out.payload)).toStrictEqual(toSign);
  });

  test("signature", async ({ page }) => {
    const out = await page.evaluate(
      async (input) => {
        const { Signer } = window.keyhive;
        const key = await Signer.generate();
        const signed = await key.trySign(new Uint8Array(input.toSign));
        return { signature: signed.signature };
      },
      { toSign },
    );

    expect(out.signature).toBeDefined();
  });

  test("round-trips through its KH frame", async ({ page }) => {
    const out = await page.evaluate(
      async (input) => {
        const { Signer, SignedBytes } = window.keyhive;
        const key = await Signer.generate();
        const frame = (await key.trySign(new Uint8Array(input.toSign))).toBytes();
        const read = SignedBytes.fromBytes(frame);
        return {
          header: Array.from(frame.slice(0, 3)),
          verified: read.verify(),
          payload: Array.from(read.payload()),
        };
      },
      { toSign },
    );

    expect(out.header).toStrictEqual([0x4b, 0x48, 0x42]); // "KHB"
    expect(out.verified).toBe(true);
    expect(out.payload).toStrictEqual(toSign);
  });

  test("a tampered frame does not verify", async ({ page }) => {
    const out = await page.evaluate(
      async (input) => {
        const { Signer, SignedBytes } = window.keyhive;
        const key = await Signer.generate();
        const frame = (await key.trySign(new Uint8Array(input.toSign))).toBytes();
        // The payload sits just before the 64-byte signature.
        frame[frame.length - 65] ^= 1;
        return { verified: SignedBytes.fromBytes(frame).verify() };
      },
      { toSign },
    );

    expect(out.verified).toBe(false);
  });
});
