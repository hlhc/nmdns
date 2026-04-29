{ lib
, rustPlatform ? null
, installShellFiles
, rust-bin
, makeRustPlatform
}:

let
  effectiveRustPlatform =
    if rustPlatform != null
    then rustPlatform
    else makeRustPlatform {
      cargo = rust-bin.stable.latest.default;
      rustc = rust-bin.stable.latest.default;
    };
in

effectiveRustPlatform.buildRustPackage {
  pname = "nmdns";
  version = "0.2.0";

  src = lib.cleanSource ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  nativeBuildInputs = [ installShellFiles ];

  # Lib unit tests + integration tests (`tests/`) all run inside the Nix
  # sandbox: they bind only ephemeral loopback sockets, never the
  # privileged mDNS port. The CLI tests exercise `--check` only, which
  # validates config and exits without binding anything.

  postInstall = ''
    installManPage man/nmdns.1
  '';

  meta = with lib; {
    description = "mDNS responder, cache, and cross-interface repeater";
    longDescription = ''
      nmdns is a multicast DNS daemon: it announces local services per
      RFC 6762, parses and TTL-tracks records seen on the wire, and can
      repeat IPv4 mDNS (224.0.0.251:5353) and IPv6 mDNS (ff02::fb:5353)
      traffic between two or more network interfaces so service discovery
      (AirPlay, Chromecast, HomeKit, printers, etc.) crosses L2 segments
      such as a trusted LAN and an IoT VLAN.
    '';
    license = with licenses; [ mit asl20 ];
    mainProgram = "nmdns";
    platforms = platforms.linux ++ platforms.darwin;
  };
}
