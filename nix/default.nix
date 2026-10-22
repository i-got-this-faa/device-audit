{ pkgs }:
let
  profiles = {
    common = import ./profiles/common.nix { inherit pkgs; };
    go = import ./profiles/go.nix { inherit pkgs; };
    models = import ./profiles/models.nix { inherit pkgs; };
    automation = import ./profiles/automation.nix { inherit pkgs; };
    networking = import ./profiles/networking.nix { inherit pkgs; };
    nix = import ./profiles/nix.nix { inherit pkgs; };
  };
  mkShell =
    name: selectedProfiles:
    pkgs.mkShellNoCC {
      name = "device-audit-${name}";
      packages = pkgs.lib.unique (profiles.common ++ pkgs.lib.concatLists selectedProfiles);
      GOTOOLCHAIN = "local";
    };
in
{
  default = mkShell "default" [
    profiles.go
    profiles.models
    profiles.automation
    profiles.nix
  ];
  go = mkShell "go" [ profiles.go ];
  models = mkShell "models" [ profiles.models ];
  automation = mkShell "automation" [ profiles.automation ];
  networking = mkShell "networking" [
    profiles.go
    profiles.networking
  ];
  nix = mkShell "nix" [ profiles.nix ];
}
