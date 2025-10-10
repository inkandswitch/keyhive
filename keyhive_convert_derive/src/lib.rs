use heck::ToSnakeCase;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, spanned::Spanned, ImplItem, ImplItemFn, ItemImpl};

#[proc_macro_attribute]
pub fn keyhive_convert(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse: #[keyhive_convert( ts = "Document" )]  (optional)
    let ts_override = parse_ts_override(attr);

    let mut impl_block = parse_macro_input!(item as ItemImpl);

    // Ensure this is an inherent impl (no trait)
    if impl_block.trait_.is_some() {
        return syn::Error::new(
            impl_block.trait_.as_ref().unwrap().1.span(),
            "#[keyhive_convert] must be used on an inherent impl, not a trait impl",
        )
        .to_compile_error()
        .into();
    }

    // Get the type name (e.g., JsDocument)
    let ty_ident = match &*impl_block.self_ty {
        syn::Type::Path(tp) => tp.path.segments.last().unwrap().ident.clone(),
        _ => {
            return syn::Error::new_spanned(&impl_block.self_ty, "expected a simple type name")
                .to_compile_error()
                .into();
        }
    };

    // Derive inferred names
    let struct_name = ty_ident.to_string();
    let core_name = struct_name
        .strip_prefix("Js")
        .unwrap_or(&struct_name)
        .to_string();
    let core_snake = core_name.to_snake_case();

    let js_interface_ident = format_ident!("{}Like", struct_name);
    let upcast_tag = format!("__keyhive_to{}", core_name);
    let method_ident = format_ident!("kh_to_{}", core_snake);
    let ts_type = ts_override.unwrap_or_else(|| core_name.clone());

    let already_present = impl_block.items.iter().any(|it| {
        if let ImplItem::Fn(ImplItemFn { sig, .. }) = it {
            sig.ident == method_ident
        } else {
            false
        }
    });

    if !already_present {
        let injected: ImplItem = syn::parse_quote! {
            #[::wasm_bindgen::prelude::wasm_bindgen(js_name = #upcast_tag)]
            pub fn #method_ident(&self) -> Self {
                self.clone()
            }
        };
        impl_block.items.push(injected);
    }

    // Extra items to emit alongside the impl:
    let extras = quote! {
        impl ::keyhive_convert_core::FromJsInterface for #ty_ident {
            type JsInterface = #js_interface_ident;

            #[inline]
            fn from_js_interface(castable: &Self::JsInterface) -> Self {
                castable.#method_ident()
            }
        }

        #[::wasm_bindgen::prelude::wasm_bindgen]
        extern "C" {
            #[::wasm_bindgen::prelude::wasm_bindgen(typescript_type = #ts_type)]
            pub type #js_interface_ident;

            #[::wasm_bindgen::prelude::wasm_bindgen(method, js_name = #upcast_tag)]
            pub fn #method_ident(this: &#js_interface_ident) -> #ty_ident;
        }
    };

    quote!(#impl_block #extras).into()
}

fn parse_ts_override(attr: TokenStream) -> Option<String> {
    let attr_str = attr.to_string();
    if attr_str.trim().is_empty() {
        return None;
    }
    let parts: Vec<_> = attr_str.split('=').map(|s| s.trim()).collect();
    if parts.len() == 2 && parts[0] == "ts" {
        let raw = parts[1].trim();
        // strip surrounding quotes if present
        let val = raw.trim_matches('"').trim_matches('\'').to_string();
        return Some(val);
    }
    None
}
