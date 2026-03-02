{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    fuse                    # System libfuse library
    python3
    python3Packages.fusepy  # Python wrapper used by fsspec
    python3Packages.fsspec  # fsspec itself
  ];
}
