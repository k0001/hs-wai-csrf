{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/46db2e09e1d3f113a13c0d7b81e2f221c63b8ce9";
    flake-parts.url = "github:hercules-ci/flake-parts";
    haskell-flake.url = "github:srid/haskell-flake";

    crypto-token.flake = false;
    crypto-token.url = "github:kazu-yamamoto/crypto-token/v0.2.0";
    crypton-certificate.flake = false;
    crypton-certificate.url = "github:kazu-yamamoto/crypton-certificate/crypton-x509-1.9.0";
    crypton-connection.flake = false;
    crypton-connection.url = "github:kazu-yamamoto/crypton-connection/v0.4.6";
    crypton.flake = false;
    crypton.url = "github:kazu-yamamoto/crypton/crypton-v1.1.2";
    hpke.flake = false;
    hpke.url = "github:kazu-yamamoto/hpke/v0.1.0";
    hs-tls.flake = false;
    hs-tls.url = "github:haskell-tls/hs-tls/tls-2.3.0";
    http-client.flake = false;
    http-client.url = "github:snoyberg/http-client/5f0d14724af440e439ce5803b941911609e766e8";
    http-semantics.flake = false;
    http-semantics.url = "github:kazu-yamamoto/http-semantics/v0.4.0";
    http2.flake = false;
    http2.url = "github:kazu-yamamoto/http2/v5.4.0";
    network-run.flake = false;
    network-run.url = "github:kazu-yamamoto/network-run/v0.5.0";
    ram.flake = false;
    ram.url = "github:jappeace/ram/fb16285c2fc303894575757786cf8f87d183b88f";
    wai.flake = false;
    wai.url = "github:yesodweb/wai/63536095e64e7703d97c8b1fb89ae8417f51090b";
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
          # "ghc948"
          # "ghc967"
          # "ghc984"
          # "ghc9102"
          "ghc9122"
          # "ghc9141"
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
              settings = {
                sandwich.check = false;
                warp.check = false;
                wai-csrf = {
                  check = true;
                  haddock = true;
                  libraryProfiling = true;
                };
              };
              packages = {
                auto-update.source = "${inputs.wai}/auto-update";
                crypto-token.source = inputs.crypto-token;
                crypton-connection.source = inputs.crypton-connection;
                crypton-x509-store.source = "${inputs.crypton-certificate}/crypton-x509-store";
                crypton-x509-system.source = "${inputs.crypton-certificate}/crypton-x509-system";
                crypton-x509-util.source = "${inputs.crypton-certificate}/crypton-x509-util";
                crypton-x509-validation.source = "${inputs.crypton-certificate}/crypton-x509-validation";
                crypton-x509.source = "${inputs.crypton-certificate}/crypton-x509";
                crypton.source = inputs.crypton;
                ech-config.source = "${inputs.hs-tls}/ech-config";
                hpke.source = inputs.hpke;
                http-client-openssl.source = "${inputs.http-client}/http-client-openssl";
                http-client-tls.source = "${inputs.http-client}/http-client-tls";
                http-client.source = "${inputs.http-client}/http-client";
                http-conduit.source = "${inputs.http-client}/http-conduit";
                http-semantics.source = inputs.http-semantics;
                http2.source = inputs.http2;
                mime-types.source = "${inputs.wai}/mime-types";
                network-run.source = inputs.network-run;
                ram.source = inputs.ram;
                recv.source = "${inputs.wai}/recv";
                time-manager.source = "${inputs.wai}/time-manager";
                tls-debug.source = "${inputs.hs-tls}/debug";
                tls-session-manager.source = "${inputs.hs-tls}/tls-session-manager";
                tls.source = "${inputs.hs-tls}/tls";
                wai-app-static.source = "${inputs.wai}/wai-app-static";
                wai-conduit.source = "${inputs.wai}/wai-conduit";
                wai-extra.source = "${inputs.wai}/wai-extra";
                wai-websockets.source = "${inputs.wai}/wai-websockets";
                wai.source = "${inputs.wai}/wai";
                warp-quic.source = "${inputs.wai}/warp-quic";
                warp-tls.source = "${inputs.wai}/warp-tls";
                warp.source = "${inputs.wai}/warp";
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
