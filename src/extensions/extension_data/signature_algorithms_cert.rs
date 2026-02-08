use crate::extensions::extension_data::signature_algorithms::SignatureScheme;

use crate::parse_encode::parse_encode_list;

parse_encode_list!(SignatureAlgorithmsCert<'a, Location>(SignatureScheme));
