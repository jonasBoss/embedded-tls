macro_rules! extension_group {
    // macro entry
    (pub enum $name:ident $( < $lt:lifetime > )? {
        $(
            $extension:ident($extension_data:ident$(<$($ext_gen:tt),*>)? )
        ),* $(,)?
    }) => {
        extension_group!(
            @enum_name $name,
            @lifetime $($lt)?,
            @location ,
            @remote ,
            @local ,
            @where_bound ,
            @extension $($extension),*,
            @ext_data $($extension_data),*,
            @ext_gene $($(< $($ext_gen),* >)?),*
        );
    };
    (pub enum $name:ident<$lt:lifetime, Location> {
        $(
            $extension:ident($extension_data:ident$(<$($ext_gen:tt),*>)? )
        ),* $(,)?
    }) => {
        extension_group!(
            @enum_name $name,
            @lifetime $lt,
            @location Location,
            @remote $crate::parse_encode::Remote,
            @local $crate::parse_encode::Local,
            @where_bound Location : $crate::parse_encode::StorageType,
            @extension $($extension),*,
            @ext_data $($extension_data),*,
            @ext_gene $($(< $($ext_gen),* >)?),*
        );
    };    // step 1a create where bound
    // step 2 impl
    (
        @enum_name $name:ident,
        @lifetime $($lt:lifetime)?,
        @location $($loc:ident)?,
        @remote $($remote:path)?,
        @local $($local:path)?,
        @where_bound $( $wt:ty : $trait:path ),*,
        @extension $($extension:ident),*,
        @ext_data $($extension_data:ident),*,
        @ext_gene $($(< $($ext_gen:tt),* >)?),*
    ) => {
        #[derive(Debug, Clone)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        #[allow(dead_code)] // extension_data may not be used
        pub enum $name< $($lt,)? $($loc)? >
        where $( $wt : $trait ),*
            {$($extension($extension_data $(< $($ext_gen),* >)? )),*}


        impl< $($lt,)? $($loc)? > $name< $($lt,)? $($loc)? >
        where $( $wt : $trait ),*
        {
            #[allow(unused)]
            pub fn extension_type(&self) -> $crate::extensions::ExtensionType {
                match self {
                    $(Self::$extension(_) => $crate::extensions::ExtensionType::$extension),*
                }
            }
        }

        #[allow(unused)]
        impl$(< $lt >)? $name< $($lt,)? $($local)? > {
            pub fn encode(self, buf: &mut $crate::buffer::CryptoBuffer) -> Result<(), $crate::TlsError> {
                self.extension_type().encode(buf)?;

                buf.with_u16_length(|buf| match self {
                    $(Self::$extension(ext_data) =>  $crate::parse_encode::Encode::encode(ext_data, buf)),*
                })
            }
        }

        #[allow(unused)] // not all types will be parsed
        impl$(< $lt >)? $name< $($lt,)? $($remote)? > {
            pub fn parse(buf: &mut $crate::parse_buffer::ParseBuffer$(< $lt >)?) -> Result<Self, $crate::TlsError>{
               // Consume extension data even if we don't recognize the extension
                let extension_type = crate::extensions::ExtensionType::parse(buf);
                let data_len = buf.read_u16().map_err(|_| crate::TlsError::DecodeError)? as usize;
                let mut ext_data = buf.slice(data_len).map_err(|_| crate::TlsError::DecodeError)?;

                let ext_type = extension_type.map_err(|err| {
                    warn!("Failed to read extension type: {:?}", err);
                    match err {
                        crate::parse_buffer::ParseError::InvalidData => crate::TlsError::UnknownExtensionType,
                        _ => crate::TlsError::DecodeError,
                    }
                })?;

                debug!("Read extension type {:?}", ext_type);
                trace!("Extension data length: {}", data_len);

                match ext_type {
                    $(crate::extensions::ExtensionType::$extension => Ok(Self::$extension($crate::parse_encode::Parse::parse(&mut ext_data).map_err(|err| {
                        warn!("Failed to parse extension data: {:?}", err);
                        crate::TlsError::DecodeError
                    })?)),)+

                    #[allow(unreachable_patterns)]
                    other => {
                        warn!("Read unexpected ExtensionType: {:?}", other);
                        // Section 4.2.  Extensions
                        // If an implementation receives an extension
                        // which it recognizes and which is not specified for the message in
                        // which it appears, it MUST abort the handshake with an
                        // "illegal_parameter" alert.
                        Err(crate::TlsError::AbortHandshake(
                            crate::alert::AlertLevel::Fatal,
                            crate::alert::AlertDescription::IllegalParameter,
                        ))
                    }
                }
            }

            pub fn parse_vector<const N: usize>(
                buf: &mut crate::parse_buffer::ParseBuffer$(<$lt>)?,
            ) -> Result<heapless::Vec<Self, N>, crate::TlsError> {
                let extensions_len = buf
                    .read_u16()
                    .map_err(|_| crate::TlsError::InvalidExtensionsLength)?;

                let mut ext_buf = buf.slice(extensions_len as usize)?;

                let mut extensions = heapless::Vec::new();

                while !ext_buf.is_empty() {
                    trace!("Extension buffer: {}", ext_buf.remaining());
                    match Self::parse(&mut ext_buf) {
                        Ok(extension) => {
                            extensions
                                .push(extension)
                                .map_err(|_| crate::TlsError::DecodeError)?;
                        }
                        Err(crate::TlsError::UnknownExtensionType) => {
                            // ignore unrecognized extension type
                        }
                        Err(err) => return Err(err),
                    }
                }

                trace!("Read {} extensions", extensions.len());
                Ok(extensions)
            }
        }
    };
}

// This re-export makes it possible to omit #[macro_export]
// https://stackoverflow.com/a/67140319
pub(crate) use extension_group;
