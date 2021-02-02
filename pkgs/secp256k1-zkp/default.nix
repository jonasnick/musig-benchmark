{ stdenv, fetchFromGitHub, autoreconfHook }:

stdenv.mkDerivation {
  pname = "secp256k1-zkp";

  version = "0.1";

  src = fetchFromGitHub {
    owner = "ElementsProject";
    repo = "secp256k1-zkp";
    rev = "ed69ea79b429beae4260917e08fe60317d38ee8d";
    sha256 = "0mwl81zx5i79yiqbc4yrr793qz10mf738dj7hl4ah59cqpw2dkkq";
  };

  nativeBuildInputs = [ autoreconfHook ];

  configureFlags = [ "--enable-experimental --enable-module-musig --enable-module-schnorrsig"  ];
}
