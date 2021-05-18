{ stdenv, secp256k1-zkp, debug ? false }:

stdenv.mkDerivation {
  name = "musig-benchmark";

  buildInputs = [ secp256k1-zkp ];

  src = ./.;

  NIX_CFLAGS_COMPILE = if debug then "-DDEBUG=1" else "";

  installPhase = ''
    mkdir -p $out/bin
    cp musig-benchmark $out/bin/
  '';
}
