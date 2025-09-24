{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    haskell-flake.url = "github:srid/haskell-flake";
  };
  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      { withSystem, ... }:
      let
        # mapListToAttrs f [a b] = {a = f a; b = f b;}
        mapListToAttrs =
          f: xs:
          builtins.listToAttrs (
            builtins.map (x: {
              name = x;
              value = f x;
            }) xs
          );
        ghcVersions = [
          "ghc984"
          "ghc9102"
          "ghc9122"
        ];
      in
      {
        systems = nixpkgs.lib.systems.flakeExposed;
        imports = [
          inputs.haskell-flake.flakeModule
        ];
        flake.haskellFlakeProjectModules = mapListToAttrs (
          ghc:
          (
            { pkgs, lib, ... }:
            withSystem pkgs.system (
              { config, ... }: config.haskellProjects.${ghc}.defaults.projectModules.output
            )
          )
        ) ghcVersions;
        perSystem =
          {
            self',
            pkgs,
            config,
            ...
          }:
          {
            haskellProjects = mapListToAttrs (ghc: {
              basePackages = pkgs.haskell.packages.${ghc};
              settings.wai-csrf = {
                check = true;
                haddock = true;
                libraryProfiling = true;
              };
              packages = {
                brick.source = "2.9";
              };
              autoWire = [
                "packages"
                "checks"
                "devShells"
              ];
              devShell = {
                tools = hp: { inherit (pkgs) cabal2nix; };
              };
            }) ghcVersions;
            packages.default = self'.packages.ghc9122-wai-csrf;
            packages.doc = self'.packages.ghc9122-wai-csrf.doc;
            devShells.default = self'.devShells.ghc9122;
          };
      }
    );
}
