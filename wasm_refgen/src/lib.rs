use heck::ToSnakeCase;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned,
    token::Comma,
    ImplItem, ImplItemFn, ItemImpl, Result, Token,
};

#[proc_macro_attribute]
pub fn wasm_refgen(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as Args);
    let js_ref_ident = args.js_ref;

    let mut impl_block = parse_macro_input!(item as ItemImpl);

    if impl_block.trait_.is_some() {
        return syn::Error::new(
            impl_block.trait_.as_ref().unwrap().1.span(),
            "#[wasm_refgen] must be used on an inherent impl, not a trait impl",
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

    let core_name = ty_ident.to_string();
    let core_snake = core_name.to_snake_case();

    let upcast_tag = format!("__wasm_refgen_to{}", core_name);
    let method_ident = format_ident!("__wasm_refgen_to_{}", core_snake);

    let already_present = impl_block.items.iter().any(|it| {
        if let ImplItem::Fn(ImplItemFn { sig, .. }) = it {
            sig.ident == method_ident
        } else {
            false
        }
    });

    if !already_present {
        let injected: ImplItem = syn::parse_quote! {
            /// Upcasts to the JS-import type for [`#ty_ident`].
            #[::wasm_bindgen::prelude::wasm_bindgen(js_name = #upcast_tag)]
            pub fn #method_ident(&self) -> Self {
                self.clone()
            }
        };
        impl_block.items.push(injected);
    }

    let extras = quote! {
        impl ::from_js_ref::FromJsRef for #ty_ident {
            type JsRef = #js_ref_ident;

            #[inline]
            fn from_js_ref(castable: &Self::JsRef) -> Self {
                castable.#method_ident()
            }
        }

        impl From<#ty_ident> for #js_ref_ident {
            fn from(v: #ty_ident) -> Self {
                ::wasm_bindgen::JsValue::from(v).unchecked_into()
            }
        }

        impl From<&#js_ref_ident> for #ty_ident {
            fn from(js_ref: &#js_ref_ident) -> Self {
                js_ref.#method_ident()
            }
        }

        /// The JS-import type for [`#ty_ident`].
        ///
        /// This lets you use the duck typed interface to convert from JS values.
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

struct Args {
    js_ref: syn::Ident,
}

impl Parse for Args {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut js_ref: Option<syn::Ident> = None;

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            if key == "js_ref" {
                js_ref = Some(input.parse()?);
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "unknown arg; expected `js_ref` or `ts`",
                ));
            }

            if input.peek(Comma) {
                let _ = input.parse::<Comma>();
            }
        }

        let js_ref = js_ref.ok_or_else(|| {
            syn::Error::new(input.span(), "missing required arg: js_ref = <Ident>")
        })?;

        Ok(Self { js_ref })
    }
}
