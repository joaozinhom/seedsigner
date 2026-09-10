{
  description = "SeedSigner uv + poe development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
    in {
      devShells = nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          libPath = pkgs.lib.makeLibraryPath (
            [ pkgs.zbar pkgs.zlib ]
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.stdenv.cc.cc.lib ]
          );
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.python312 pkgs.uv pkgs.git ];

            UV_PYTHON = "${pkgs.python312}/bin/python3.12";
            UV_PYTHON_DOWNLOADS = "never";
            # Keep the Nix interpreter separate from an existing host venv.
            UV_PROJECT_ENVIRONMENT = ".venv/nix";

            shellHook = ''
              export ${if pkgs.stdenv.isDarwin then "DYLD_LIBRARY_PATH" else "LD_LIBRARY_PATH"}="${libPath}"
              if uv sync --locked --group l10n; then
                if [ -d src/seedsigner/resources/seedsigner-translations/l10n ]; then
                  uv run --no-sync poe translations-compile
                else
                  echo "Fetch translations: git submodule update --init --recursive"
                  echo "Then run: uv run poe translations-compile"
                fi
              fi
              echo "SeedSigner: uv run poe test (or uv run poe for all tasks)"
            '';
          };
        });
    };
}
