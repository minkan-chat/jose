{ pkgs, ... }:
{
  packages = with pkgs; [
    step-cli
    cargo-deny
    cargo-shear
    cargo-udeps
    cargo-hack
    cargo-nextest

    openssl
    pkg-config
    cmake
    rustPlatform.bindgenHook
  ];

  enterTest = ''
    cargo clippy
    cargo test
  '';

  languages.rust = {
    enable = true;
    channel = "nightly";
    components = [
      "rustc"
      "cargo"
      "clippy"
      "rustfmt"
      "rust-src"
    ];
  };
}
