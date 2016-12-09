#!/usr/bin/env bash

bin="$(mktemp -t option-generate)"
go build -o "${bin}" "./cmd/option-generate"

function generate {
  local name="${1}"
  local type="${2}"
  "${bin}" "${name}" "${type}" "${type}.go"
}

generate "Bool" "bool"
generate "Error" "error"
generate "Float32" "float32"
generate "Float64" "float64"
generate "Int" "int"
generate "Int8" "int8"
generate "Int16" "int16"
generate "Int32" "int32"
generate "Int64" "int64"
generate "String" "string"
generate "Uint" "uint"
generate "Uint8" "uint8"
generate "Uint16" "uint16"
generate "Uint32" "uint32"
generate "Uint64" "uint64"
