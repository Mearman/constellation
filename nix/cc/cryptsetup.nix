{ pkgs, buildEnv, closureInfo }:
let
  lib = pkgs.lib;
  packages = [ pkgs.cryptsetup.out pkgs.cryptsetup.dev ];
  closure = builtins.toString (lib.strings.splitString "\n" (builtins.readFile "${closureInfo {rootPaths = packages;}}/store-paths"));
  rpath = pkgs.lib.makeLibraryPath [ pkgs.cryptsetup pkgs.glibc pkgs.libgcc.lib ];
in
pkgs.symlinkJoin {
  name = "cryptsetup";
  paths = [ pkgs.cryptsetup.out pkgs.cryptsetup.dev ];
  buildInputs = packages;
  postBuild = ''
    tar -cf $out/closure.tar ${closure}
    echo "${rpath}" > $out/rpath
  '';
}
