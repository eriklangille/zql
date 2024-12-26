import { promises as fs } from 'fs';
import { DatabaseSync } from 'node:sqlite';
import loadZQL from '../zql.js';

const SMALL_DB_FILE = './test.db';
const BACKUP_DB_FILE = './backup.db';
const BIG_DB_FILE = './example.db';
let zql;
let zqlResult = [];
let sql;

async function getFile(name) {
  try {
    const data = await fs.readFile(name);
    return data.buffer;
  } catch (error) {
    throw new Error(`File read error: ${error.message}`);
  }
}

async function compare(query) {
  await zql.exec(query);
  const sqlQuery = sql.prepare(query);
  const sqlResult = sqlQuery.all();
  console.log(zqlResult);
  expect(zqlResult.length).toBe(sqlResult.length);
  for (let i = 0; i < sqlResult.length; i++) {
    const obj = sqlResult[i];
    let j = 0;
    for (const key in obj) {
      const sqlItem = obj[key];
      let zqlItem = zqlResult[i][j];
      if (typeof zqlItem == 'bigint') {
        zqlItem = Number(zqlItem);
      }
      expect(zqlItem).toBe(sqlItem);
      j++;
    }
  }
  // clear the array
  zqlResult = [];
}

async function load(dbFile) {
  console.log("Loading SQLite");
  sql = new DatabaseSync(dbFile);
  zql = await loadZQL();
  const addTableRow = (array) => {
    zqlResult.push(array);
  }
  zql.rowListeners.push(addTableRow);
  await zql.loadFile(getFile(dbFile));
  console.log("Loaded");
}

describe('Compare ZQL to SQL', () => {
  test('small db', async () => {
    await load(SMALL_DB_FILE)
    await compare("select * from example;");
    await compare("select id, name from example;");
    await compare("select id from example;");
    await compare("select name from example;");
    await compare("select * from example where id = 1;");
    await compare("select * from example where name = 'Alice';");
    await compare("select * from example where name = 'Alice' or name = 'Bob';");
    await compare("select * from example where name like 'A%'");
    await compare("select * from example where name like '%l%'");
  });
  test('backup db', async () => {
    await load(BACKUP_DB_FILE)
    await compare("select * from test;");
  });
  test('example db', async () => {
    await load(BIG_DB_FILE)
    await compare("select * from records;");
  });
});

