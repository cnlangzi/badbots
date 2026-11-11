#!/bin/sh
# Rewrites the version references of the repository and prints the rewritten files.
set -eu

cd "$(dirname "$0")/.."

usage() {
    printf 'usage: scripts/set-version.sh <version>\n' >&2
    printf '       <version> is x.y.z or x.y.z-<suffix>, for example 0.1.0 or 0.3.0-alpha.1\n' >&2
}

invalid() {
    printf "error: '%s' is not a valid version, expected x.y.z or x.y.z-<suffix>\n" "$1" >&2
    usage
    exit 2
}

if [ "$#" -ne 1 ]; then
    usage
    exit 2
fi

version="$1"

case "$version" in
    *[[:space:]]*) invalid "$version" ;;
esac

if [ -z "$(printf '%s' "$version" | sed -n -E '/^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/p')" ]; then
    invalid "$version"
fi

major_minor=$(printf '%s' "$version" | sed -E 's/^([0-9]+\.[0-9]+)\..*$/\1/')

rewrite() {
    sed -i.bak -E "$1" "$2"
    rm -f "$2.bak"
}

rewrite "s|^version = \"[^\"]*\"\$|version = \"$version\"|" Cargo.toml
files="Cargo.toml"

case "$version" in
    *-*) ;;
    *)
        for doc in README.md docs/providers/*.md; do
            rewrite "s|badbots = [{] version = \"[^\"]*\"|badbots = { version = \"$major_minor\"|" "$doc"
            files="$files $doc"
        done
        ;;
esac

for file in $files; do
    printf '%s\n' "$file"
done
