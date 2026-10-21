{
  description = "Device Audit development dependency profiles";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          config = { };
          overlays = [ ];
        };
    in
    {
      devShells = forAllSystems (system: import ./nix { pkgs = pkgsFor system; });
      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);
    };
}
