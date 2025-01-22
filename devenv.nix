{pkgs, ...}: {
  packages = with pkgs; [
    step-cli
    cargo-deny
  ];

  enterTest = ''
    cargo clippy
    cargo test
  '';

  languages.rust = {
    enable = true;
    channel = "nightly";
    components = ["rustc" "cargo" "clippy" "rustfmt" "rust-src"];
  };
}
