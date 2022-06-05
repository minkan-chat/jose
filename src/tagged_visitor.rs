use alloc::{collections::BTreeMap, fmt, vec::Vec};
use core::marker::PhantomData;

use serde::{
    de::{self, DeserializeSeed, Error as _, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_value::{DeserializerError, Value, ValueVisitor};

macro_rules! impl_internally_tagged_deserialize {
    ($T:ty, $tag:literal, $expecting:literal, [$($name:literal => $i:ident),* $(,)?]) => {
        #[allow(warnings)]
        impl<'de> serde::Deserialize<'de> for $T {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                #[derive(Clone, Copy, Deserialize)]
                enum Tag {
                    $(#[serde(rename = $name)]
                    $i,)*
                }

                let tagged =
                    deserializer.deserialize_any(TaggedContentVisitor::new($tag, $expecting))?;

                match tagged.tag {
                    $(Tag::$i => Deserialize::deserialize(tagged.content).map(<$T>::$i),)*
                    //Tag::P256 => Deserialize::deserialize(tagged.content).map(Self::P256),
                    //Tag::P384 => Deserialize::deserialize(tagged.content).map(Self::P384),
                    //Tag::Secp256k1 => Deserialize::deserialize(tagged.content).map(Self::Secp256k1),
                }
                .map_err(|x| x.into_error())
            }
        }
    };
}

pub(crate) struct TaggedContent<T> {
    pub tag: T,
    pub content: Value,
}

pub(crate) struct TaggedContentVisitor<'de, T> {
    tag_name: &'static str,
    expecting: &'static str,
    _tag: PhantomData<T>,
    _content: PhantomData<&'de [u8]>,
}

impl<'de, T> TaggedContentVisitor<'de, T> {
    pub fn new(tag_name: &'static str, expecting: &'static str) -> Self {
        Self {
            tag_name,
            expecting,
            _tag: PhantomData,
            _content: PhantomData,
        }
    }
}

impl<'de, T> DeserializeSeed<'de> for TaggedContentVisitor<'de, T>
where
    T: Deserialize<'de> + Clone,
{
    type Value = TaggedContent<T>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Internally tagged enums are only supported in self-describing
        // formats.
        deserializer.deserialize_any(self)
    }
}

impl<'de, T> Visitor<'de> for TaggedContentVisitor<'de, T>
where
    T: Deserialize<'de> + Clone,
{
    type Value = TaggedContent<T>;

    fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.expecting)
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut tag = None;
        let mut content = BTreeMap::new();

        while let Some(k) = map.next_key::<Value>()? {
            let val = if matches!(k, Value::String(ref s) if s == self.tag_name) {
                let val = map.next_value::<Value>()?;
                tag = Some(val.clone().deserialize_into().map_err(|e| e.into_error())?);
                val
            } else {
                map.next_value()?
            };

            content.insert(k, val);
        }

        match tag {
            None => Err(de::Error::missing_field(self.tag_name)),
            Some(tag) => Ok(TaggedContent {
                tag,
                content: Value::Map(content),
            }),
        }
    }
}
