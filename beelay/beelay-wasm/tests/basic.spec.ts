import { expect } from "chai";
import * as path from "path";
import {
  Beelay,
  MemorySigner,
  MemoryStorageAdapter,
  type Stream,
  type Commit,
  type StorageAdapter,
  type StorageKey,
  type CommitOrBundle,
  type DocumentId,
} from "./pkg/beelay_wasm.js";
import { createHash } from "crypto";
import { kill } from "process";

describe("Beelay WASM Basic Tests", () => {
  let beelay: Beelay;

  beforeEach(async () => {
    const storage = new MemoryStorageAdapter();
    const signer = new MemorySigner();
    beelay = await Beelay.load({ storage, signer });
  });

  afterEach(async () => {
    beelay.stop();
  });

  it("should create a Beelay instance", async () => {
    expect(beelay).to.be.an("object");
  });

  it("should return the correct version", async () => {
    const version = beelay.version();
    expect(version).to.equal("0.1.0");
  });

  it("should create a document", async () => {
    const doc = await beelay.createDoc({
      initialCommit: commit("hello world"),
    });
    expect(doc).to.be.a("string");
  });

  describe("bundling", () => {
    it("should request bundles", async () => {
      let bundleRequested = false;
      let lastCommit = commit("hello world");
      const doc = await beelay.createDoc({
        initialCommit: lastCommit,
      });
      while (!bundleRequested) {
        lastCommit = commit("next bit", [lastCommit.hash]);
        const specs = await beelay.addCommits({
          docId: doc,
          commits: [lastCommit],
        });
        bundleRequested = specs.length > 0;
      }
    });

    it("should allow creating bundles from specs", async () => {
      let bundleSpec = null;
      let lastCommit = commit("hello world");
      const doc = await beelay.createDoc({
        initialCommit: lastCommit,
      });
      while (bundleSpec == null) {
        lastCommit = commit("next bit", [lastCommit.hash]);
        const specs = await beelay.addCommits({
          docId: doc,
          commits: [lastCommit],
        });
        if (specs.length > 0) {
          bundleSpec = specs[0];
        }
      }
      let bundle = {
        start: bundleSpec.start,
        end: bundleSpec.end,
        contents: new Uint8Array([0, 1, 2, 3, 4]),
        checkpoints: bundleSpec.checkpoints,
      };
      await beelay.addBundle({ docId: doc, bundle });
    });
  });

  describe("two connected peers", () => {
    let beelays: Array<Beelay> = [];

    async function create(): Promise<Beelay> {
      const storage = new MemoryStorageAdapter();
      const signer = new MemorySigner();
      const result = await Beelay.load({ storage, signer });
      beelays.push(result);
      return result;
    }

    beforeEach(() => {
      beelays = [];
    });

    afterEach(async () => {
      for (const beelay of beelays) {
        await beelay.stop();
      }
    });

    it("should synchronise documents between them", async () => {
      let alice = await create();
      let bob = await create();
      let aliceContactCard = await alice.createContactCard();
      let initialCommit = commit("hello world");
      const doc = await bob.createDoc({
        initialCommit,
        otherParents: [{ type: "individual", contactCard: aliceContactCard }],
      });

      connect(alice, bob);
      await alice.waitUntilSynced(bob.peerId);

      const docOnAlice = await alice.loadDocument(doc);
      expect(docOnAlice).to.deep.equal([{ type: "commit", ...initialCommit }]);
    });

    it("should forward added commits to listening peers", async () => {
      let alice = await create();
      let bob = await create();
      let aliceNotifications: { docId: DocumentId; data: CommitOrBundle }[] =
        [];
      alice.on("doc-event", ({ docId, event }) => {
        if (event.type === "data") {
          aliceNotifications.push({ docId: docId, data: event.data });
        }
      });

      let aliceContactCard = await alice.createContactCard();
      let initialCommit = commit("hello world");
      const doc = await bob.createDoc({
        initialCommit,
        otherParents: [{ type: "individual", contactCard: aliceContactCard }],
      });

      connect(alice, bob);
      await alice.waitUntilSynced(bob.peerId);

      expect(aliceNotifications).to.deep.equal([
        {
          docId: doc,
          data: {
            type: "commit",
            ...initialCommit,
          },
        },
      ]);
      aliceNotifications = [];

      let nextCommit = commit("hello again world", [initialCommit.hash]);
      await bob.addCommits({ docId: doc, commits: [nextCommit] });

      // TODO: make this less fragile
      await pause(10);

      expect(aliceNotifications).to.deep.equal([
        {
          docId: doc,
          data: {
            type: "commit",
            ...nextCommit,
          },
        },
      ]);
    });

    it("should sync documents in groups", async () => {
      let alice = await create();
      let bob = await create();
      let group = await alice.createGroup();
      let bobContactCard = await bob.createContactCard();
      await alice.addMember({
        groupId: group,
        member: { type: "individual", contactCard: bobContactCard },
        access: "write",
      });

      let initialCommit = commit("hello world");
      const doc = await alice.createDoc({
        initialCommit,
        otherParents: [{ type: "group", id: group }],
      });

      connect(bob, alice);
      await bob.waitUntilSynced(alice.peerId);

      const docOnBob = await bob.loadDocument(doc);
      expect(docOnBob).to.deep.equal([{ type: "commit", ...initialCommit }]);
    });

    it.skip("should not sync groups we have been removed from", async () => {
      let alice = await create();
      let bob = await create();
      let group = await alice.createGroup();
      let bobContactCard = await bob.createContactCard();
      await alice.addMember({
        groupId: group,
        member: { type: "individual", contactCard: bobContactCard },
        access: "write",
      });
      await alice.removeMember({
        groupId: group,
        member: { type: "individual", contactCard: bobContactCard },
      });

      let initialCommit = commit("hello world");
      const doc = await alice.createDoc({
        initialCommit,
        otherParents: [{ type: "group", id: group }],
      });

      connect(bob, alice);
      await bob.waitUntilSynced(alice.peerId);

      const docOnBob = await bob.loadDocument(doc);
      expect(docOnBob).to.be.null;
    });

    it("should sync sub documents", async () => {
      let alice = await create();
      let bob = await create();
      let superDoc = await alice.createDoc({
        initialCommit: commit("hello group"),
      });
      let bobContactCard = await bob.createContactCard();
      await alice.addMember({
        docId: superDoc,
        member: { type: "individual", contactCard: bobContactCard },
        access: "write",
      });

      let initialCommit = commit("hello world");
      const doc = await alice.createDoc({
        initialCommit,
        otherParents: [{ type: "document", id: superDoc }],
      });

      connect(bob, alice);
      await bob.waitUntilSynced(alice.peerId);

      const docOnBob = await bob.loadDocument(doc);
      expect(docOnBob).to.deep.equal([{ type: "commit", ...initialCommit }]);
    });

    describe("waitForDocument", () => {
      it("should return once the document is available", async () => {
        let alice = await create();
        let bob = await create();
        let aliceContactCard = await alice.createContactCard();
        let initialCommit = commit("hello world");
        const doc = await bob.createDoc({
          initialCommit,
          otherParents: [{ type: "individual", contactCard: aliceContactCard }],
        });

        const whenLoaded = alice.waitForDocument(doc);

        let beforeConnect = await Promise.race([whenLoaded, pause(10)]);
        expect(beforeConnect).to.be.undefined;

        connect(alice, bob);

        const docOnAlice = await whenLoaded;
        expect(docOnAlice).to.deep.equal([
          { type: "commit", ...initialCommit },
        ]);
      });
    });
  });
});

function connect(left: Beelay, right: Beelay) {
  let { port1: leftToRight, port2: rightToLeft } = new MessageChannel();
  leftToRight.start();
  rightToLeft.start();

  function connectStream(stream: Stream, port: MessagePort) {
    stream.on("message", (message) => {
      port.postMessage(message);
    });
    port.onmessage = (event) => {
      stream.recv(new Uint8Array(event.data));
    };
    stream.on("disconnect", () => {
      port.close();
    });
  }

  let leftStream = left.createStream({
    direction: "connecting",
    remoteAudience: {
      type: "peerId",
      peerId: right.peerId,
    },
  });
  connectStream(leftStream, leftToRight);

  let rightStream = right.createStream({
    direction: "accepting",
  });
  connectStream(rightStream, rightToLeft);
}

function commit(contents: string, parents: string[] = []): Commit {
  const hash = createHash("sha256")
    .update(contents)
    .update(parents.join(""))
    .digest("hex");
  const contentsAsUint8Array = new Uint8Array(Buffer.from(contents, "utf-8"));
  return {
    parents,
    hash,
    contents: contentsAsUint8Array,
  };
}

async function pause(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
