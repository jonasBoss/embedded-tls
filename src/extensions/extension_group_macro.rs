/// simple helper trait that allows us to convert `Option<T>` to `Result<T>` or  `Result<Option<T>>` with a call to `maybe_ok_or`
/// the `Result<Option<T>>` will never error
pub trait MaybeOk<R> {
    fn maybe_ok_or<E>(self, err: E) -> Result<R, E>;
}
impl<R> MaybeOk<Option<R>> for Option<R> {
    fn maybe_ok_or<E>(self, _: E) -> Result<Option<R>, E> {
        Ok(self)
    }
}
impl<R> MaybeOk<R> for Option<R> {
    fn maybe_ok_or<E>(self, err: E) -> Result<R, E> {
        self.ok_or(err)
    }
}

pub trait ExtensionEncode {
    fn extension_encode(self, buf: &mut CryptoBuffer, ext: ExtensionType) -> Result<(), TlsError>;
}
impl<T: Encode> ExtensionEncode for T {
    fn extension_encode(self, buf: &mut CryptoBuffer, ext: ExtensionType) -> Result<(), TlsError> {
        ext.encode(buf)?;
        buf.with_u16_length(|buf| self.encode(buf))
    }
}
impl<T: Encode> ExtensionEncode for Option<T> {
    fn extension_encode(self, buf: &mut CryptoBuffer, ext: ExtensionType) -> Result<(), TlsError> {
        let _ = self
            .map(|t| {
                ext.encode(buf)?;
                buf.with_u16_length(|buf| t.encode(buf))
            })
            .transpose()?;
        Ok(())
    }
}

macro_rules! extension_group {

    // entry without a `Location` generic
    (
        $(#[$attr:meta])*
        pub struct $name:ident $( < $lt:lifetime > )? {
            $( $body:tt )*
        }
    )
    => {
        extension_group!(
            [
                @name $name,
                @lifetime $($lt)?,
                @location ,
                @remote ,
                @local ,
                @where_bound ,
                @attr $($attr)*,
                @body { $( $body )* },
            ],
            @extensions {},
            @to_parse $( $body )*
        );
    };
    // entry with a `Location` generic
    (
        $(#[$attr:meta])*
        pub struct $name:ident < $lt:lifetime, Location > {
            $( $body:tt )*
        }
    )
    => {
        extension_group!(
            [
                @name $name,
                @lifetime $lt,
                @location Location,
                @remote $crate::parse_encode::Remote,
                @local $crate::parse_encode::Local,
                @where_bound Location : $crate::parse_encode::StorageType,
                @attr $($attr)*,
                @body { $( $body )* },
            ],
            @extensions {},
            @to_parse $( $body )*
        );
    };

    // process a optional extension
    (
        [ $($data:tt)* ], // this matches @name, @lifetime, ...
        @extensions { $( $extensions:ident )* },
        @to_parse $(#[$meta:meta])* $vis:vis $_:ident : Option<$ext:ident<$($inner:tt),*>> $(, $($rest:tt)*)?
    ) => {
        extension_group!(
            [ $( $data )* ],
            @extensions { $($extensions)* $ext },
            @to_parse $($($rest)*)?
        );
    };

    // process a optional extension without generics
    (
        [ $($data:tt)* ], // this matches @name, @lifetime, ...
        @extensions { $( $extensions:ident )* },
        @to_parse $(#[$meta:meta])* $vis:vis $_:ident : Option<$ext:ident> $(, $($rest:tt)*)?
    ) => {
        extension_group!(
            [ $( $data )* ],
            @extensions { $($extensions)* $ext },
            @to_parse $($($rest)*)?
        );
    };

    // process a mandatory extension
    (
        [ $($data:tt)* ], // this matches @name, @lifetime, ...
        @extensions { $( $extensions:ident )* },
        @to_parse $(#[$meta:meta])* $vis:vis $_:ident : $ext:ident<$($inner:tt),*> $(, $($rest:tt)*)?
    ) => {
        extension_group!(
            [ $( $data )* ],
            @extensions { $($extensions)* $ext },
            @to_parse $($($rest)*)?
        );
    };

    // process a mandatory extension without generics
    (
        [ $($data:tt)* ], // this matches @name, @lifetime, ...
        @extensions { $( $extensions:ident )* },
        @to_parse $(#[$meta:meta])* $vis:vis $_:ident : $ext:ident $(, $($rest:tt)*)?
    ) => {
        extension_group!(
            [ $( $data )* ],
            @extensions { $($extensions)* $ext },
            @to_parse $($($rest)*)?
        );
    };

    // final step, code generation
    (
        [
            @name $name:ident,
            @lifetime $($lt:lifetime)?,
            @location $($loc:ident)?,
            @remote $($remote:path)?,
            @local $($local:path)?,
            @where_bound $( $wt:ty : $trait:path ),*,
            @attr $($attr:meta)*,
            @body { $( $(#[$_:meta])* $vis:vis $field:ident : $f_type:ty ),* $(,)? },
        ],
        @extensions { $($ext:ident)* },
        @to_parse //empty
    ) => {

        $(#[$attr])*
        pub struct $name< $($lt)? $(, $loc)? >
        where $( $wt : $trait),*
        {
            $( $vis $field : $f_type ),*
        }

        impl < $($lt)? > $crate::parse_encode::Parse< $($lt)? > for $name< $($lt)? $(, $remote)? >
        {
            fn parse(buf: &mut $crate::parse_buffer::ParseBuffer< $($lt)? >) -> Result<Self, $crate::parse_buffer::ParseError> {
                $( let mut $field = None;)*

                let len = buf.read_u16()? as usize;
                let mut buf = buf.slice(len)?;

                while buf.remaining() > 0 {
                    let ext_type = $crate::extensions::ExtensionType::parse(&mut buf);
                    let ext_len = buf.read_u16()? as usize;
                    let mut ext_data = buf.slice(ext_len)?;

                    let ext_type = match ext_type.inspect_err(|e| warn!("Failed to read extension type: {:?}", e)) {
                        Ok(ext_type) => ext_type,
                        Err($crate::parse_buffer::ParseError::InvalidData) => continue,
                        Err(e) => return Err(e),
                    };

                    debug!("Read extension type {:?}", ext_type);
                    trace!("Extension data length: {}", ext_len);

                    match ext_type {
                        $(
                            $crate::extensions::ExtensionType::$ext => {
                                if $field.is_some() {
                                    return Err($crate::parse_buffer::ParseError::InvalidData);
                                }
                                $field = Some(
                                    $ext::parse(&mut ext_data)
                                    .inspect_err(|e|warn!("Failed to parse extension data: {:?}", e))?
                                );
                            }
                        )*
                        #[allow(unreachable_patterns)]
                        other => {
                            warn!("Read unexpected ExtensionType: {:?}", other);
                            // Section 4.2.  Extensions
                            // If an implementation receives an extension
                            // which it recognizes and which is not specified for the message in
                            // which it appears, it MUST abort the handshake with an
                            // "illegal_parameter" alert.
                            return Err($crate::parse_buffer::ParseError::InvalidData); // TODO: abort handshake error
                        }
                    };
                }
                Ok(Self {
                    $(
                        $field : $crate::extensions::extension_group_macro::MaybeOk::maybe_ok_or(
                            $field,
                            $crate::parse_buffer::ParseError::InvalidData
                        )?,
                    )*
                })
            }
        }

        impl< $($lt)? > $crate::parse_encode::Encode for $name< $($lt)? $(, $local)? > {
            fn encode(self, buf: &mut $crate::buffer::CryptoBuffer) -> Result<(), $crate::TlsError> {
                buf.with_u16_length(|buf|{
                    $(
                        $crate::extensions::extension_group_macro::ExtensionEncode::extension_encode(
                            self.$field, buf, $crate::extensions::ExtensionType::$ext
                        )?;
                    )*
                    Ok(())
                })
            }
        }
    };
}

// This re-export makes it possible to omit #[macro_export]
// https://stackoverflow.com/a/67140319
pub(crate) use extension_group;

use crate::{TlsError, buffer::CryptoBuffer, extensions::ExtensionType, parse_encode::Encode};
