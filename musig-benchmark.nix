{ stdenv, secp256k1-zkp }:

stdenv.mkDerivation {
  name = "musig-benchmark";

  buildInputs = [ secp256k1-zkp ];

  src = ./.;

  installPhase = ''
    mkdir -p $out/bin
    cp musig-benchmark $out/bin/
  '';
}
