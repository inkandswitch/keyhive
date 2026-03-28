// IndexedDB wrapper for keyhive secret key persistence.
//
// Stores X25519 secret key bytes keyed by hex-encoded public key.
// Uses a single object store "secret_keys" in a database "keyhive_keys".

const DB_NAME = "keyhive_keys";
const DB_VERSION = 1;
const STORE_NAME = "secret_keys";

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/**
 * Load all key pairs from IndexedDB.
 * @returns {Promise<Array<[string, Uint8Array]>>} Array of [hex_public_key, secret_key_bytes]
 */
export async function idb_load_all_keys() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.getAll();
    const keysRequest = store.getAllKeys();

    const results = { values: null, keys: null };

    request.onsuccess = () => {
      results.values = request.result;
      if (results.keys !== null) {
        resolve(results.keys.map((k, i) => [k, results.values[i]]));
      }
    };

    keysRequest.onsuccess = () => {
      results.keys = keysRequest.result;
      if (results.values !== null) {
        resolve(results.keys.map((k, i) => [k, results.values[i]]));
      }
    };

    tx.onerror = () => reject(tx.error);
  });
}

/**
 * Store a secret key in IndexedDB.
 * @param {string} public_key_hex - Hex-encoded public key (used as the IDB key)
 * @param {Uint8Array} secret_key_bytes - Raw 32-byte X25519 secret key
 */
export async function idb_store_key(public_key_hex, secret_key_bytes) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    store.put(secret_key_bytes, public_key_hex);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/**
 * Check if a key exists in IndexedDB.
 * @param {string} public_key_hex - Hex-encoded public key
 * @returns {Promise<boolean>}
 */
export async function idb_has_key(public_key_hex) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.getKey(public_key_hex);
    request.onsuccess = () => resolve(request.result !== undefined);
    tx.onerror = () => reject(tx.error);
  });
}
