{
  description = "Applied cryptography - assignment 1, block ciphers and chaining modes";

  inputs = {
    nixpkgs.url = "github:cipharius/nixpkgs/static-haskell-patch";
  };

  outputs = { self, nixpkgs }: {
    defaultPackage.x86_64-linux =
      with import nixpkgs { system = "x86_64-linux"; };
      stdenv.mkDerivation {
        name = "hcrypter";
        src = self;
        isLibrary = false;
        isExecutable = true;
        enableSharedExecutables = false;
        enableSharedLibraries = false;
        buildInputs = [
          (pkgsMusl.haskellPackages.ghcWithPackages (pkgs: with pkgs; [
            bits-bytestring
            bytestring
            cryptonite
            optparse-applicative
          ]))
        ];
        buildPhase = ''ghc \
          -optl=-static \
          -Wall \
          -Werror \
          -L${pkgsMusl.gmp6.override { withStatic = true; }}/lib \
          -L${pkgsMusl.zlib.static}/lib \
          -L${pkgsMusl.libffi.overrideAttrs (old: { dontDisableStatic = true; })}/lib \
          -o hcrypter \
          -ilib \
          ./app/Main.hs
        '';
        installPhase = "mkdir -p $out/bin; install -t $out/bin hcrypter";
      };
  };
}
