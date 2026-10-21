# Package definition shared by flake.nix and pkgs.callPackage ./step-web { }.
{
  lib,
  buildNpmPackage,
  nodejs_24,
  openssl,
}:

buildNpmPackage {
  pname = "step-web";
  meta = {
    description = "Static OIDC enrollment page for step-ca certificates";
    license = lib.licenses.mit;
  };
  version = (builtins.fromJSON (builtins.readFile ./package.json)).version;
  outputs = [ "out" "nginx" ];

  allowSubstitutes = false;  # No prebuilt binaries at least for now

  # Do not copy local configuration, node_modules, or an existing dist build.
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./package.json
      ./package-lock.json
      ./.npmrc
      ./LICENSE
      ./src
      ./scripts
      ./test
    ];
  };

  nodejs = nodejs_24;
  npmDepsHash = "sha256-vW+gSp5OzINE/SBW9id1MZL4c+6jKmpXtxwYK2NMxWc=";

  # npmConfigHook runs both ci and rebuild. Disable dependency lifecycle hooks
  # in both, while still allowing our explicitly selected build/test scripts.
  env.npm_config_ignore_scripts = "true";
  npmRebuildFlags = [ "--ignore-scripts" ];

  doCheck = true;
  nativeCheckInputs = [ openssl ];
  checkPhase = ''
    runHook preCheck
    npm test
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    cp -r dist/. "$out/"
    moveToOutput "nginx.conf" "$nginx"
    runHook postInstall
  '';
}
