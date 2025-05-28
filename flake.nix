{
  description = "MagicEntry dev shell";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system: {
        devShells.default = with nixpkgs.legacyPackages.${system}; mkShell {
          packages = [
            cargo
            rustup
            rust-analyzer
            openssl.dev
            pkg-config

            cargo-audit
            gnuplot # For benchmarks
            hurl
          ];
        };
      });
}
