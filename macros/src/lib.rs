use proc_macro::TokenStream;
use proc_macro_error2::proc_macro_error;
use syn::{DeriveInput, parse_macro_input};

mod derive_serializable;

#[proc_macro_derive(Serializable, attributes(maker, wrapped))]
#[proc_macro_error]
pub fn serializable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_serializable::derive_serializable(input).into()
}
