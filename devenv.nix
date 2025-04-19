{ pkgs, ... }:
{
  packages = with pkgs; [
    step-cli
    cargo-deny
    cargo-shear
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
