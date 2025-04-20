with import <nixpkgs> {};
let
  # Required until this is fixed: https://github.com/KWARC/rust-libxml/issues/147
  libxml2_older = libxml2.overrideAttrs (old: rec {
    version = "2.10.4";
    src = fetchurl {
      url = "mirror://gnome/sources/libxml2/2.10/${old.pname}-${version}.tar.xz";
      sha256 = "sha256-7QyRxYRQCPGTZznk7uIDVTHByUdCxlQfRO5m2IWUjUU=";
    };
  });
in mkShell {
  nativeBuildInputs = [
    rustup
    openssl.dev
    pkg-config

    libxml2_older

    llvmPackages_latest.lldb
    llvmPackages_latest.libllvm
    llvmPackages_latest.libcxx
    llvmPackages_latest.clang
  ];

  # Use clang instead of GCC
  stdenv = pkgs.clangStdenv;

  shellHook = ''
    # From: https://hoverbear.org/blog/rust-bindgen-in-nix/
    # From: https://github.com/NixOS/nixpkgs/blob/1fab95f5190d087e66a3502481e34e15d62090aa/pkgs/applications/networking/browsers/firefox/common.nix#L247-L253
    # Set C flags for Rust's bindgen program. Unlike ordinary C
    # compilation, bindgen does not invoke $CC directly. Instead it
    # uses LLVM's libclang. To make sure all necessary flags are
    # included we need to look in a few places.
    export BINDGEN_EXTRA_CLANG_ARGS="$(< ${stdenv.cc}/nix-support/libc-crt1-cflags) \
      $(< ${stdenv.cc}/nix-support/libc-cflags) \
      $(< ${stdenv.cc}/nix-support/cc-cflags) \
      $(< ${stdenv.cc}/nix-support/libcxx-cxxflags) \
      ${lib.optionalString stdenv.cc.isClang "-idirafter ${stdenv.cc.cc}/lib/clang/${lib.getVersion stdenv.cc.cc}/include"} \
      ${lib.optionalString stdenv.cc.isGNU "-isystem ${stdenv.cc.cc}/include/c++/${lib.getVersion stdenv.cc.cc} -isystem ${stdenv.cc.cc}/include/c++/${lib.getVersion stdenv.cc.cc}/${stdenv.hostPlatform.config} -idirafter ${stdenv.cc.cc}/lib/gcc/${stdenv.hostPlatform.config}/${lib.getVersion stdenv.cc.cc}/include"} \
    "

    export LIBCLANG_PATH="${llvmPackages.libclang.lib}/lib";
  '';
}
