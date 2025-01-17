# `libsm-js`

[![npm (scoped)](https://img.shields.io/npm/v/@lifeni/libsm-js)](https://www.npmjs.com/package/@lifeni/libsm-js)

A WebAssembly Library of SM2, SM3 and SM4. Based on [`libsm`](https://github.com/citahub/libsm).

## Usage

Install [`@lifeni/libsm-js`](https://www.npmjs.com/package/@lifeni/libsm-js) in your project.

```sh
npm i @lifeni/libsm-js
# yarn add @lifeni/libsm-js
# pnpm add @lifeni/libsm-js
```

## Build & Publish

```sh
git clone --recurse-submodules https://github.com/bluegitter/libsm-js
cd libsm-js
wasm-pack build --target web --scope lifeni
cd pkg
npm publish --access=public
```

## Test

```sh
 wasm-pack test --node
```

## License

This project is licensed under either of

- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
