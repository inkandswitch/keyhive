# Development

## JavaScript Package Layout

`wasm-pack` does not generate a single JavaScript package which can be used in
every environment, instead you must choose the environment you are building for
using the `--target` flag. This is not at all what we want because it makes it
very difficult to transitively depend on keyhive, which is something we expect
lots of packages to do.

To get around this we use conditional exports. We build the package for each
environment we care about (currently `bundler` and `nodejs`) and then include
each build package in the built package. Then we use the `"exports"` field in
`package.json` to choose which package is used at load time. This does lead
to a larger package size.

## Release Process

Releases are automatically pushed to NPM by GitHub Actions when a release is
created in the repository. Releases which are for a tag beginning with
`keyhive-wasm` are pushed to NPM, others are ignored.
