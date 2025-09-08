{
  description = "MagicEntry dev shell";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { nixpkgs, flake-utils, ... }:
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
          watchexec
          sqlx-cli

          libxml2
          clang

          yarn-berry
        ];

        nativeBuildInputs = with pkgs; [ pkg-config ];

        shellHook = ''
          export DATABASE_URL="sqlite://database.db"
          export LIBCLANG_PATH="${pkgs.libclang.lib}/lib";
        '';
      };
    });
}
