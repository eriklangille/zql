import { promises as fs } from 'fs';
import { DatabaseSync } from 'node:sqlite';
import loadZQL from '../zql.js';

const DB_FILE = './test.db';
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

beforeAll(async () => {
  console.log("Loading SQLite");
  sql = new DatabaseSync(DB_FILE);
  zql = await loadZQL();
  const addTableRow = (array) => {
    zqlResult.push(array);
  }
  zql.rowListeners.push(addTableRow);
  await zql.loadFile(getFile(DB_FILE));
  console.log("Loaded");
});

describe('Compare ZQL to SQL', () => {
  test('example db', async () => {
    await compare("select * from example;");
    await compare("select id, name from example;");
    await compare("select id from example;");
    await compare("select name from example;");
    await compare("select * from example where name = 'Alice';");
    await compare("select * from example where name = 'Alice' or name = 'Bob';");
  });
});

