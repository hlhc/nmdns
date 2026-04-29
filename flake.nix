{
  description = "nmdns - mDNS repeater daemon";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    in
    {
      overlays.default = final: prev:
        let
          rustToolchain = final.rust-bin.stable.latest.default;
          rustPlatform = final.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
        in
        {
          nmdns = final.callPackage ./nix/package.nix { inherit rustPlatform; };
        };

      nixosModules.default = ./nix/module.nix;
      nixosModules.nmdns = ./nix/module.nix;
    } // flake-utils.lib.eachSystem systems (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            rust-overlay.overlays.default
            self.overlays.default
          ];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default;
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
          packages = [
            rustToolchain
            pkgs.rustfmt
            pkgs.clippy
            pkgs.rust-analyzer
          ];
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };

        checks.build = pkgs.nmdns;
      });
}
