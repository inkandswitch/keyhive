use std::collections::HashMap;

use beelay_core::StorageKey;
use js_sys::{Array, Function, JsString, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsError, JsValue};
use wasm_bindgen_futures::JsFuture;

#[derive(Clone)]
pub(crate) struct JsStorage {
    this: JsValue,
    load: Function,
    load_range: Function,
    list_one_level: Function,
    remove: Function,
    save: Function,
}

impl JsStorage {
    pub(crate) fn new(obj: JsValue) -> Result<Self, JsError> {
        // Check the target is an objecto
        if !obj.has_type::<Object>() {
            return Err(JsError::new("storage adapter must be an object"));
        }

        let load = Reflect::get(&obj, &"load".into())
            .unwrap()
            .dyn_into::<Function>()
            .map_err(|_| JsError::new("load must be a function"))?;
        let load_range = Reflect::get(&obj, &"loadRange".into())
            .unwrap()
            .dyn_into::<Function>()
            .map_err(|_| JsError::new("loadRange must be a function"))?;
        let list_one_level = Reflect::get(&obj, &"listOneLevel".into())
            .unwrap()
            .dyn_into::<Function>()
            .map_err(|_| JsError::new("listOneLevel must be a function"))?;
        let remove = Reflect::get(&obj, &"remove".into())
            .unwrap()
            .dyn_into::<Function>()
            .map_err(|_| JsError::new("remove must be a function"))?;
        let save = Reflect::get(&obj, &"save".into())
            .unwrap()
            .dyn_into::<Function>()
            .map_err(|_| JsError::new("save must be a function"))?;
        Ok(Self {
            this: obj,
            load,
            load_range,
            list_one_level,
            remove,
            save,
        })
    }

    pub(crate) async fn load(&self, key: StorageKey) -> Result<Option<Vec<u8>>, JsError> {
        let key = key.components().map(JsValue::from).collect::<Array>();
        let result = self
            .load
            .call1(&self.this, &key)
            .map_err(|e| JsError::new(&format!("load failed: {:?}", e)))?;
        let promise = result
            .dyn_into::<Promise>()
            .map_err(|_| JsError::new("load must return a promise"))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| JsError::new(&format!("load failed: {:?}", e)))?;

        if result.is_null() || result.is_undefined() {
            return Ok(None);
        }

        let value = result
            .dyn_into::<Uint8Array>()
            .map_err(|_| JsError::new("load must return a uint8array or null"))?;

        Ok(Some(value.to_vec()))
    }

    pub(crate) async fn load_range(
        &self,
        prefix: StorageKey,
    ) -> Result<HashMap<StorageKey, Vec<u8>>, JsError> {
        let prefix = prefix.components().map(JsValue::from).collect::<Array>();
        let result = self
            .load_range
            .call1(&self.this, &prefix.into())
            .map_err(|e| JsError::new(&format!("load_range failed: {:?}", e)))?;
        let promise = result
            .dyn_into::<Promise>()
            .map_err(|_| JsError::new("load_range must return a promise"))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| JsError::new(&format!("load_range failed: {:?}", e)))?;

        let value = result
            .dyn_into::<js_sys::Map>()
            .map_err(|_| JsError::new("load_range must return a Map"))?;

        let map = value
            .entries()
            .into_iter()
            .map(|item| {
                let entry = item
                    .expect("failed to iterate over map entries")
                    .dyn_into::<Array>()
                    .expect("A map entry is an array of two elements");
                let key = entry
                    .get(0)
                    .dyn_into::<Array>()
                    .map_err(|_| JsError::new("load_range returned an invalid key"))?;
                let value = entry
                    .get(1)
                    .dyn_into::<Uint8Array>()
                    .map_err(|_| JsError::new("load_range must return a map of uint8arrays"))?;
                let key = key
                    .dyn_into::<Array>()
                    .map_err(|_| JsError::new("load_range must return an array of strings"))?;

                let key_components = key
                    .into_iter()
                    .map(|component| {
                        Ok(component
                            .dyn_into::<JsString>()
                            .map_err(|_| {
                                JsError::new("load_range must return an array of strings")
                            })?
                            .into())
                    })
                    .collect::<Result<Vec<String>, JsError>>()?;
                let key = StorageKey::try_from(key_components)
                    .map_err(|e| JsError::new(&format!("bad storage key: {:?}", e)))?;

                Ok((key, value.to_vec()))
            })
            .collect::<Result<HashMap<StorageKey, Vec<u8>>, JsError>>()?;

        Ok(map)
    }

    pub(crate) async fn list_one_level(
        &self,
        prefix: StorageKey,
    ) -> Result<Vec<StorageKey>, JsError> {
        let prefix = prefix.components().map(JsValue::from).collect::<Array>();
        let result = self
            .list_one_level
            .call1(&self.this, &prefix.into())
            .map_err(|e| JsError::new(&format!("list_one_level failed: {:?}", e)))?;
        let promise = result
            .dyn_into::<Promise>()
            .map_err(|_| JsError::new("list_one_level must return a promise"))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| JsError::new(&format!("list_one_level failed: {:?}", e)))?;

        let value = result
            .dyn_into::<Array>()
            .map_err(|_| JsError::new("list_one_level must return an array"))?;
        let keys = value
            .into_iter()
            .map(|key| {
                let key_components_arr = key.dyn_into::<Array>().map_err(|_| {
                    JsError::new("list_one_level must return an array of arrays of strings")
                })?;
                let key_components = key_components_arr
                    .iter()
                    .map(|component| {
                        Ok(component
                            .dyn_into::<JsString>()
                            .map_err(|_| {
                                JsError::new(
                                    "list_one_level must return an array of arrays of strings",
                                )
                            })?
                            .into())
                    })
                    .collect::<Result<Vec<String>, JsError>>()?;
                StorageKey::try_from(key_components)
                    .map_err(|e| JsError::new(&format!("Failed to create StorageKey: {:?}", e)))
            })
            .collect::<Result<Vec<StorageKey>, JsError>>()?;

        Ok(keys)
    }

    pub(crate) async fn remove(&self, key: StorageKey) -> Result<(), JsError> {
        let key = key.components().map(JsValue::from).collect::<Array>();
        let promise = self
            .remove
            .call1(&self.this, &key)
            .map_err(|_| JsError::new("error calling remove"))?
            .dyn_into::<Promise>()
            .map_err(|_| JsError::new("remove must return a Promise"))?;

        JsFuture::from(promise)
            .await
            .map_err(|e| JsError::new(&format!("remove failed: {:?}", e)))?;

        Ok(())
    }

    pub(crate) async fn put(&self, key: StorageKey, value: Vec<u8>) -> Result<(), JsError> {
        let key = key.components().map(JsValue::from).collect::<Array>();
        let value = Uint8Array::from(value.as_slice());

        let promise = self
            .save
            .call2(&self.this, &key, &value)
            .map_err(|_| JsError::new("error calling put"))?
            .dyn_into::<Promise>()
            .map_err(|_| JsError::new("put must return a Promise"))?;

        JsFuture::from(promise)
            .await
            .map_err(|e| JsError::new(&format!("put failed: {:?}", e)))?;

        Ok(())
    }
}

#[wasm_bindgen]
pub struct MemoryStorageAdapter {
    data: HashMap<StorageKey, Vec<u8>>,
}

#[wasm_bindgen]
impl MemoryStorageAdapter {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    #[wasm_bindgen]
    pub async fn load(&self, key: JsValue) -> Result<JsValue, JsError> {
        let key = parse_key(key)?;
        if let Some(data) = self.data.get(&key) {
            Ok(Uint8Array::from(data.as_slice()).into())
        } else {
            Ok(JsValue::null())
        }
    }

    #[wasm_bindgen(js_name = "loadRange")]
    pub async fn load_range(&self, prefix: JsValue) -> Result<JsValue, JsError> {
        let prefix = parse_key(prefix)?;
        let result = js_sys::Map::new();
        for (k, v) in self.data.iter() {
            if prefix.is_prefix_of(k) {
                let key = Array::new();
                for component in k.components() {
                    key.push(&JsValue::from(&component.to_string()));
                }
                let value = Uint8Array::from(v.as_slice());
                result.set(&key, &value);
            }
        }
        Ok(result.into())
    }

    #[wasm_bindgen]
    pub async fn save(&mut self, key: JsValue, data: JsValue) -> Result<(), JsError> {
        let key = parse_key(key)?;
        let value = data
            .dyn_into::<Uint8Array>()
            .map_err(|_| JsError::new("data was not a Uint8Array"))?;
        self.data.insert(key, value.to_vec());
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn remove(&mut self, key: JsValue) -> Result<(), JsError> {
        let key = parse_key(key)?;
        self.data.remove(&key);
        Ok(())
    }

    #[wasm_bindgen(js_name = "listOneLevel")]
    pub async fn list_one_level(&self, prefix: JsValue) -> Result<JsValue, JsError> {
        let prefix = parse_key(prefix)?;
        let result = Array::new();
        for key in self.data.keys() {
            if let Some(key) = key.onelevel_deeper(&prefix) {
                result.push(&key.to_string().into());
            }
        }
        Ok(result.into())
    }
}

fn parse_key(key: JsValue) -> Result<StorageKey, JsError> {
    let components = key
        .dyn_into::<Array>()
        .map_err(|_| JsError::new("storage key should be an array"))?
        .iter()
        .map(|item| {
            item.dyn_into::<JsString>()
                .map_err(|_| JsError::new("storage key should be an array of strings"))
                .map(|i| i.into())
        })
        .collect::<Result<Vec<String>, JsError>>()?;

    StorageKey::try_from(components)
        .map_err(|e| JsError::new(&format!("invalid storage key: {}", e)))
}
