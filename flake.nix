{
  description = "nmdns - mDNS repeater daemon";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    in
    {
      overlays.default = final: prev: {
        nmdns = final.callPackage ./nix/package.nix { };
      };

      nixosModules.default = ./nix/module.nix;
      nixosModules.nmdns = ./nix/module.nix;
    } // flake-utils.lib.eachSystem systems (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ self.overlays.default ];
        };
      in
      {
        packages = {
          default = pkgs.nmdns;
          nmdns = pkgs.nmdns;
        };

        apps.default = {
          type = "app";
          program = "${pkgs.nmdns}/bin/nmdns";
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
          ];
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };

        checks.build = pkgs.nmdns;
      });
}
