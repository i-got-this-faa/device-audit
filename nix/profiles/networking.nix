{ pkgs }:
pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux (
  with pkgs;
  [
    strace
    gawk
  ]
)
