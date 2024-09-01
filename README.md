# ZQL

SQLite File Reader natively built for use in the browser. Maybe this will be something more one day..

## How to build

Make sure to add more `--export`s to include the functions you want to export to the web assembly module.

```bash
zig build-exe zql.zig -target wasm32-freestanding -fno-entry  --export=runStatementWithFile --export=getStatementAddr --export=malloc
```

One can also use the [build mode](https://ziglang.org/documentation/master/#Build-Mode) to build a release version of the program.

```bash
zig build-exe zql.zig -target wasm32-freestanding -O ReleaseSmall  -fno-entry  --export=runStatementWithFile --export=getStatementAddr --export=malloc
```

and then run a web server

```bash
python3 -m http.server
```

open the browser and navigate to `http://localhost:8000/zql.html`

### Access SQLite Database

`../sqlite/sqlite3 test.db "select * from example;"`

`test.db` contains a table `example` with 2 columns (id primary index, name string) and 3 entries (Alice, Bob, Charlie)
