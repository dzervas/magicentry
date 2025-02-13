with import <nixpkgs> {};
mkShell {
  nativeBuildInputs = [
    rustup
    openssl.dev
    pkg-config
    gcc
  ];
}
