use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemStruct, ItemEnum, parse_macro_input};

/// Generate a typed_cache implementation for a struct with TTL support
///
/// Usage:
/// ```rust
/// #[typed_cache(ttl = 300)]
/// struct MyType {
///     id: i32,
///     name: String,
/// }
/// ```
#[proc_macro_attribute]
pub fn typed_cache(args: TokenStream, input: TokenStream) -> TokenStream {
    let struct_def = parse_macro_input!(input as ItemStruct);
    let struct_name = &struct_def.ident;

    // Parse the TTL from the attribute arguments
    let ttl_seconds = parse_ttl_from_args(args);

    // Generate a compile-time hash based on the structure
    let struct_hash = generate_struct_hash(&struct_def);

    let ttl_impl = if let Some(ttl) = ttl_seconds {
        quote! {
            fn default_ttl() -> Option<std::time::Duration> {
                Some(std::time::Duration::from_secs(#ttl))
            }
        }
    } else {
        quote! {
            fn default_ttl() -> Option<std::time::Duration> {
                None
            }
        }
    };

    let expanded = quote! {
        #struct_def

        impl crate::cache::object::CachedObject for #struct_name {
            fn cache_type_hash() -> u64 {
                #struct_hash
            }

            fn cache_prefix() -> &'static str {
                stringify!(#struct_name)
            }

            #ttl_impl
        }
    };

    TokenStream::from(expanded)
}

fn parse_ttl_from_args(args: TokenStream) -> Option<u64> {
    if args.is_empty() {
        return None;
    }

    // Simple string parsing approach - more robust for basic cases
    let args_str = args.to_string();

    // Look for "ttl = 300" pattern
    if args_str.contains("ttl") {
        // Simple parsing for "ttl = number"
        if let Some(equals_pos) = args_str.find('=') {
            let number_part = args_str[equals_pos + 1..].trim();
            if let Ok(ttl_value) = number_part.parse::<u64>() {
                return Some(ttl_value);
            }
        }
    }

    None
}

fn generate_struct_hash(input: &ItemStruct) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    // Hash the type name
    input.ident.to_string().hash(&mut hasher);

    // Hash generics
    for param in &input.generics.params {
        format!("{:?}", param).hash(&mut hasher);
    }

    // Hash fields
    match &input.fields {
        syn::Fields::Named(fields) => {
            for field in &fields.named {
                // Hash field name
                if let Some(ident) = &field.ident {
                    ident.to_string().hash(&mut hasher);
                }
                // Hash field type
                format!("{:?}", field.ty).hash(&mut hasher);
            }
        }
        syn::Fields::Unnamed(fields) => {
            for (index, field) in fields.unnamed.iter().enumerate() {
                // Hash field index for unnamed fields
                index.hash(&mut hasher);
                // Hash field type
                format!("{:?}", field.ty).hash(&mut hasher);
            }
        }
        syn::Fields::Unit => {
            // Unit struct - just hash the name (already done above)
        }
    }

    hasher.finish()
}

/// Generate a typed counter implementation for an enum with TTL support
///
/// Usage:
/// ```rust
/// #[typed_counter(ttl = 3600)]
/// enum UsageField {
///     requests,
///     input_tokens,
///     output_tokens,
///     cost_cents,
/// }
/// ```
#[proc_macro_attribute]
pub fn typed_counter(args: TokenStream, input: TokenStream) -> TokenStream {
    let enum_def = parse_macro_input!(input as ItemEnum);
    let enum_name = &enum_def.ident;

    // Parse the TTL from the attribute arguments (reuse existing function)
    let ttl_seconds = parse_ttl_from_args(args);

    // Collect all enum variants
    let variants: Vec<_> = enum_def.variants.iter().collect();

    // Generate match arms for field_name method
    let field_name_arms = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let field_name = variant_ident.to_string();
        quote! {
            #enum_name::#variant_ident => #field_name
        }
    });

    // Generate all_fields vector
    let all_fields_variants = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        quote! {
            #enum_name::#variant_ident
        }
    });

    // Generate TTL implementation
    let ttl_impl = if let Some(ttl) = ttl_seconds {
        quote! {
            fn default_ttl() -> Option<std::time::Duration> {
                Some(std::time::Duration::from_secs(#ttl))
            }
        }
    } else {
        quote! {
            fn default_ttl() -> Option<std::time::Duration> {
                None
            }
        }
    };

    let expanded = quote! {
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        #enum_def

        impl crate::cache::counter::CounterField for #enum_name {
            fn field_name(&self) -> &'static str {
                match self {
                    #(#field_name_arms,)*
                }
            }

            fn all_fields() -> Vec<Self> {
                vec![
                    #(#all_fields_variants,)*
                ]
            }

            fn counter_prefix() -> &'static str {
                stringify!(#enum_name)
            }

            #ttl_impl
        }
    };

    TokenStream::from(expanded)
}
