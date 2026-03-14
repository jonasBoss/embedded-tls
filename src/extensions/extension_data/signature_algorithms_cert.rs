use crate::extensions::extension_data::signature_algorithms::SignatureScheme;

use crate::parse_encode::make_zerocopy_list;

make_zerocopy_list! {
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct SignatureAlgorithmsCert<'a, Location>(SignatureScheme);
}
