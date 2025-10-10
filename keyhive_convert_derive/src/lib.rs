use heck::ToSnakeCase;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, spanned::Spanned, ImplItem, ImplItemFn, ItemImpl};

#[proc_macro_attribute]
pub fn keyhive_convert(_attr: TokenStream, item: TokenStream) -> TokenStream {
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

    let struct_name = ty_ident.to_string();
    let core_name = struct_name
        .strip_prefix("Js")
        .unwrap_or(&struct_name)
        .to_string();
    let core_snake = core_name.to_snake_case();

    let js_ref_ident = format_ident!("{}Ref", struct_name);
    let upcast_tag = format!("__keyhive_to{}", core_name);
    let method_ident = format_ident!("__keyhive_to_{}", core_snake);

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

    let extras = quote! {
        impl ::keyhive_convert_core::FromJsRef for #ty_ident {
            type JsRef = #js_ref_ident;

            #[inline]
            fn from_js_ref(castable: &Self::JsRef) -> Self {
                castable.#method_ident()
            }
        }

        #[::wasm_bindgen::prelude::wasm_bindgen]
        extern "C" {
            #[::wasm_bindgen::prelude::wasm_bindgen(typescript_type = #core_name)]
            pub type #js_ref_ident;

            #[::wasm_bindgen::prelude::wasm_bindgen(method, js_name = #upcast_tag)]
            pub fn #method_ident(this: &#js_ref_ident) -> #ty_ident;
        }
    };

    quote!(#impl_block #extras).into()
}
