{ config, lib, pkgs, ... }:

let
  cfg = config.services.nmdns;
  pkg = cfg.package;

  # Build the TOML config from typed options. Anything passed in `settings`
  # is merged on top, so users can set fields the module doesn't expose.
  baseSettings = {
    foreground = true; # systemd handles supervision
    interfaces = cfg.interfaces;
    repeat = cfg.repeat;
    blacklist = cfg.blacklist;
    whitelist = cfg.whitelist;
    browse = cfg.browse;
    service = cfg.services;
  } // lib.optionalAttrs (cfg.hostname != null) { hostname = cfg.hostname; };

  finalSettings = lib.recursiveUpdate baseSettings cfg.settings;

  configFile = (pkgs.formats.toml { }).generate "nmdns.toml" finalSettings;
in
{
  options.services.nmdns = {
    enable = lib.mkEnableOption "nmdns mDNS responder/repeater";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.nmdns or (pkgs.callPackage ./package.nix { });
      defaultText = lib.literalExpression "pkgs.nmdns";
      description = "The nmdns package to use.";
    };

    interfaces = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      example = [ "br-lan" "br-iot" ];
      description = ''
        Network interfaces the daemon listens on. mDNS traffic will be
        received and (when `repeat` is enabled) forwarded between every pair.
      '';
    };

    repeat = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Forward unparsed/unknown mDNS traffic between interfaces. Set to
        false for pure responder-only operation.
      '';
    };

    hostname = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "router";
      description = ''
        Hostname advertised as `<hostname>.local.` on every interface.
        Defaults to the system hostname.
      '';
    };

    blacklist = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "10.0.0.0/8" ];
      description = "Source subnets whose packets are dropped.";
    };

    whitelist = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "192.168.50.0/24" ];
      description = "Only forward packets from these source subnets.";
    };

    browse = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "_services._dns-sd._udp.local." ];
      description = ''
        Service types the daemon actively browses for, keeping the cache warm.
      '';
    };

    services = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          name = lib.mkOption {
            type = lib.types.str;
            description = "Instance name (shown to users).";
          };
          service = lib.mkOption {
            type = lib.types.str;
            example = "_http._tcp.local.";
            description = "DNS-SD service type (must end with `.local.`).";
          };
          port = lib.mkOption {
            type = lib.types.port;
            description = "TCP/UDP port advertised in the SRV record.";
          };
          txt = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            example = [ "path=/" ];
            description = "TXT record key=value entries.";
          };
          host = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "Override target host. Defaults to daemon hostname.";
          };
        };
      });
      default = [ ];
      description = "DNS-SD services to publish.";
    };

    settings = lib.mkOption {
      type = (pkgs.formats.toml { }).type;
      default = { };
      description = ''
        Free-form TOML overrides merged on top of the typed options.
        Use this for keys the module doesn't expose directly.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "nmdns";
      description = ''
        System user the systemd unit runs as. Granted the
        `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW` ambient capabilities so it
        can bind UDP/5353 and use `SO_BINDTODEVICE` without root.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open UDP 5353 on the specified `interfaces`.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.interfaces != [ ];
        message = "services.nmdns.interfaces must not be empty.";
      }
      {
        assertion = !(cfg.blacklist != [ ] && cfg.whitelist != [ ]);
        message = "services.nmdns: blacklist and whitelist are mutually exclusive.";
      }
    ];

    users.users = lib.mkIf (cfg.user == "nmdns") {
      nmdns = {
        isSystemUser = true;
        group = "nmdns";
        description = "nmdns mDNS responder";
      };
    };
    users.groups = lib.mkIf (cfg.user == "nmdns") { nmdns = { }; };

    networking.firewall.interfaces = lib.mkIf cfg.openFirewall (
      lib.listToAttrs (map (i: lib.nameValuePair i {
        allowedUDPPorts = [ 5353 ];
      }) cfg.interfaces)
    );

    environment.systemPackages = [ pkg ];
    environment.etc."nmdns.toml".source = configFile;

    systemd.services.nmdns = {
      description = "nmdns mDNS responder";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkg}/bin/nmdns -f -c ${configFile}";
        Restart = "on-failure";
        RestartSec = 5;

        User = cfg.user;
        Group = cfg.user;

        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" "CAP_NET_RAW" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" "CAP_NET_RAW" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
      };
    };
  };
}
