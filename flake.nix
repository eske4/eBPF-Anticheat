{
  description = "TyrSecure eBPF Project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "TyrSecure";
          version = "0.1.0";
          src = ./.;

          nativeBuildInputs = with pkgs; [ cmake pkg-config clang bpftools ];
          buildInputs = with pkgs; [ libbpf elfutils zlib fmt ];

          # eBPF specific: prevents compiler from adding incompatible security flags
          hardeningDisable = [ "stackprotector" "fortify" ];
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          packages = with pkgs; [ gdb clang-tools ];
        };
      });
}
