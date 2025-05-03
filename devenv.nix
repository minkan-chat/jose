{ pkgs, ... }:
{
  packages = with pkgs; [
    step-cli
    cargo-deny
    cargo-shear
    cargo-udeps
    cargo-hack
    cargo-nextest
    cargo-tarpaulin

    jose

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

  scripts = {
    each-crypto.exec = ''
      CRYPTO_FEATURES="$(cat Cargo.toml | grep -o 'crypto-[^ ]* =' | tr -d ' =' | paste -sd ',')"

      cargo hack \
        --each-feature \
        --include-features $CRYPTO_FEATURES \
        "$@"
    '';

    jwk-thumbprints.exec = ''
      # write a script, that takes a list of files as arguments
      # and calculates sha256, sha384 and sha512 thumbprints
      # for each file, and prints the result in a table
      # the script should be called jwk-thumbprints

      files="$@"

      if [ -z "$files" ]; then
        echo "No files provided"
        exit 1
      fi

      for file in $files; do
        if [ ! -f "$file" ]; then
          echo "$file is not a file"
          continue
        fi
        
        echo "$file"

        sha256=$(jose jwk thp -a S256 -i "$file")
        sha384=$(jose jwk thp -a S384 -i "$file")
        sha512=$(jose jwk thp -a S512 -i "$file")

        echo -e "\tSHA256: $sha256"
        echo -e "\tSHA384: $sha384"
        echo -e "\tSHA512: $sha512"
        echo -e "\n"
      done
    '';
  };
}
