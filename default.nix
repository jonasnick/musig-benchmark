{ pkgs ? import <nixpkgs> {} }:

rec {
  secp256k1-zkp = pkgs.callPackage ./pkgs/secp256k1-zkp { };
  musig-benchmark = pkgs.callPackage ./musig-benchmark.nix { inherit secp256k1-zkp; };
  musig-benchmark-debug = pkgs.callPackage ./musig-benchmark.nix { inherit secp256k1-zkp; debug = true; };
}
