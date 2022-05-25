use self::{
    curve25519::{Curve25519Private, Curve25519Public},
    curve448::{Curve448Private, Curve448Public},
};

pub mod curve25519 {
    pub mod ed25519 {
        #[derive(Debug)]
        pub struct Ed25519PublicKey;

        #[derive(Debug)]
        pub struct Ed25519PrivateKey;
    }
    pub mod x25519 {
        #[derive(Debug)]
        pub struct X25519PublicKey;

        #[derive(Debug)]
        pub struct X25519PrivateKey;
    }

    #[derive(Debug)]
    pub enum Curve25519Public {
        Ed(ed25519::Ed25519PublicKey),
        X(x25519::X25519PublicKey),
    }

    #[derive(Debug)]
    pub enum Curve25519Private {
        Ed(ed25519::Ed25519PrivateKey),
        X(x25519::X25519PrivateKey),
    }
}

// TODO: unsupported, no implementation available
pub mod curve448 {
    pub mod ed448 {

        #[derive(Debug)]
        pub struct Ed448Public;

        #[derive(Debug)]
        pub struct Ed448Private;
    }
    pub mod x448 {
        #[derive(Debug)]
        pub struct X448Public;

        #[derive(Debug)]
        pub struct X448Private;
    }

    #[derive(Debug)]
    pub enum Curve448Public {
        Ed(ed448::Ed448Public),
        X(x448::X448Public),
    }

    #[derive(Debug)]
    pub enum Curve448Private {
        Ed(ed448::Ed448Private),
        X(ed448::Ed448Private),
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum OkpPublic {
    Curve25519(Curve25519Public),
    Curve448(Curve448Public),
}

#[non_exhaustive]
#[derive(Debug)]
pub enum OkpPrivate {
    Curve25519(Curve25519Private),
    Curve448(Curve448Private),
}
