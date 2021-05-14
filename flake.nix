{
  description = "Applied cryptography - assignment 1, block ciphers and chaining modes";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-20.09";
  };

  outputs = { self, nixpkgs }: {
    defaultPackage.x86_64-linux =
      with import nixpkgs { system = "x86_64-linux"; };
      stdenv.mkDerivation {
        name = "hcrypter";
        src = self;
        buildInputs = [
          (haskellPackages.ghcWithPackages (pkgs: [ pkgs.cryptonite ]))
        ];
        buildPhase = "ghc -v -o hcrypter -ilib ./app/Main.hs";
        installPhase = "mkdir -p $out/bin; install -t $out/bin hcrypter";
      };
  };
}
