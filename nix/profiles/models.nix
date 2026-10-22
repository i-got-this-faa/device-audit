{ pkgs }:
[
  (pkgs.python312.withPackages (
    ps: with ps; [
      jsonschema
      rfc3339-validator
    ]
  ))
]
