{ stdenv, fetchFromGitHub, autoreconfHook }:

stdenv.mkDerivation {
  pname = "secp256k1-zkp";

  version = "0.1";

  src = fetchFromGitHub {
     owner = "jonasnick";
     repo = "secp256k1-zkp";
     rev = "2301071766eefb1c2cac836e21a0f514d8ccda81";
     sha256 = "0zkb0igdxgzwpbxff6xspam8yphqv5k6xfqwxsgggrff5w9d3xiw";
   };

  nativeBuildInputs = [ autoreconfHook ];

  configureFlags = [ "--enable-experimental --enable-module-musig"  ];
}
