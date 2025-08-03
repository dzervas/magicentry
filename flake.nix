{
  description = "MagicEntry dev shell";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system: {
        devShells.default = with nixpkgs.legacyPackages.${system}; mkShell {
          packages = [
            cargo
            rustc
            rustup
            rust-analyzer
            openssl.dev perl
            pkg-config

            cargo-audit
            cargo-criterion
            gnuplot # For benchmarks
            hurl

            yarn
          ];
        };
      });
}
