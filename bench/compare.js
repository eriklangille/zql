import { run, bench, boxplot } from 'mitata';
import { promises as fs } from 'fs';
import { Database } from 'node-sqlite3-wasm';
import loadZQL from '../zql.js';

let zql;
let sql;
let zqlResult = [];

async function getFile(name) {
  try {
    const data = await fs.readFile(name);
    return data.buffer;
  } catch (error) {
    throw new Error(`File read error: ${error.message}`);
  }
}

async function load(dbFile) {
  zql = await loadZQL();
  sql = new Database(dbFile, { fileMustExist: true });
  const addTableRow = (array) => {
    zqlResult.push(array);
  }
  zql.rowListeners.push(addTableRow);
  await zql.loadFile(getFile(dbFile));
}

await load('./example.db');

function benchQuery(query) {
  bench(`[zql] ${query}`, async () => await zql.exec(query));
  bench(`[sqlite] ${query}`, () => {
    sql.all(query);
  });
}

benchQuery("select * from records;");
benchQuery("select * from records where id > 9000;");
benchQuery("select * from records where name like '%a';");

await run();
