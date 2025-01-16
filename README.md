# ZQL

Query SQLite databases from your web browser.

SQLite basic `Select` command functionality written in Zig that compiles to the web browser via web assembly.

## How to build

The release version:
```bash
zig build -Doptimize=ReleaseFast
```

Comparison tests against SQLite can be run using `NPM`:
```bash
npm install && npm test 
```

### Run in a web browser:

Symlink the `zql.wasm` output file to the repo root directory:
```bash
ln -s zig-out/bin/zql.wasm zql.wasm
```

Then host the root directory using a basic web server. For e.g.:
```bash
python3 -m http.server
```

Then open the browser and navigate to `http://localhost:8000/zql.html`

### Web browser debugging

To debug the WASM build, open the browser DevTools and navigate to the `Console` tab.
Build using `npm run debug` to get console log output. This will slow performance by a lot.
Console log includes output of instruction generation, equivalent to the `explain` keyword.

Select `Disable cache` under the `Network` tab when rebuilding the WASM file

## Benchmarking

Run `npm run bench` to benchmark performance against SQLite.

