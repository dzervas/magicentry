{ pkgs, ... }: {
  languages = {
    rust.enable = true;
    javascript.enable = true;
    javascript.yarn.enable = true;
  };

  packages = with pkgs; [
    cargo-audit
    cargo-criterion
    gnuplot # For benchmarks
    hurl
    watchexec
    sqlx-cli
    tailwindcss_4

    openssl.dev perl
    libxml2

    clang
  ];

  env = {
    DATABASE_URL="sqlite://database.db";
    LIBCLANG_PATH="${pkgs.libclang.lib}/lib";

    HURL_base_url = "http://127.0.0.1:8080";
    HURL_fixture_url = "http://127.0.0.1:8080/secrets";
  };

  scripts = {
    db-reinit.exec = "rm -f database.db*; cargo sqlx db create; cargo sqlx migrate run; cargo sqlx prepare";
  };
}
