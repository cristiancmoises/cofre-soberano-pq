{
  lib,
  rustPlatform,
  withPkcs11 ? true,
}:

rustPlatform.buildRustPackage {
  pname = "cofre-soberano-pq";
  version = (builtins.fromTOML (builtins.readFile ../../Cargo.toml)).workspace.package.version;

  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../Cargo.toml
      ../../Cargo.lock
      ../../crates
      ../../docs
      ../../screenshots
      ../../README.md
      ../../README.pt-BR.md
      ../../LICENSE-AGPL
      ../../NOTICE
    ];
  };

  cargoLock.lockFile = ../../Cargo.lock;
  cargoBuildFlags = [ "--workspace" ];
  cargoTestFlags = [ "--workspace" ];
  buildFeatures = lib.optional withPkcs11 "qgateway/pkcs11";

  postInstall = ''
    install -Dm644 LICENSE-AGPL "$out/share/licenses/cofre-soberano-pq/LICENSE-AGPL"
    install -Dm644 NOTICE "$out/share/doc/cofre-soberano-pq/NOTICE"
    install -m644 README.md README.pt-BR.md "$out/share/doc/cofre-soberano-pq/"
    cp -r docs "$out/share/doc/cofre-soberano-pq/"
    cp -r screenshots "$out/share/doc/cofre-soberano-pq/"
  '';

  meta = {
    description = "Post-quantum signed audit logs and TCP gateway";
    homepage = "https://git.securityops.co/cristiancmoises/cofre-soberano-pq";
    license = lib.licenses.agpl3Plus;
    mainProgram = "qaudit";
    platforms = lib.platforms.linux;
  };
}
