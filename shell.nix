with import <nixpkgs> {};
mkShell {
  packages = [
    rustup
    rust-analyzer
    openssl.dev
    pkg-config

    cargo-audit
  ];
}
