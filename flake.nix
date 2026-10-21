{
  description = "Static OIDC enrollment page for step-ca certificates";

  inputs = {
    systems.url = "systems";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, systems }:
    let
      forAllSystems = nixpkgs.lib.genAttrs (import systems);
    in {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          step-web = pkgs.callPackage ./. { };
        in {
          inherit step-web;
          default = step-web;
        });

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) step-web;
      });

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShellNoCC {
            packages = [ pkgs.nodejs_24 pkgs.openssl ];
            OPENSSL = nixpkgs.lib.getExe pkgs.openssl;
          };
        });
    };
}
