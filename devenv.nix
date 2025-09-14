{ pkgs, ... }: {
  languages = {
    rust.enable = true;
    javascript = {
      enable = true;
      yarn.enable = true;
    };
  };

  env = {
    LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
  };

  packages = with pkgs; [
    openssl.dev perl # OpenSSL needs it
    libxml2
    clang

    cargo-audit
    cargo-criterion
    gnuplot # For benchmarks
    hurl
    watchexec
    sqlx-cli
  ];
}
