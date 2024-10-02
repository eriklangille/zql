import { promises as fs } from 'fs';
import { DatabaseSync } from 'node:sqlite';
import loadZQL from '../zql.js';

const DB_FILE = './test.db';
let zql;
let sql;

async function getFile(name) {
  try {
    const data = await fs.readFile(name);
    return data.buffer;
  } catch (error) {
    throw new Error(`File read error: ${error.message}`);
  }
}

beforeAll(async () => {
  console.log("Loading SQLite");
  sql = new DatabaseSync(DB_FILE);
  zql = await loadZQL();
  const addTableRow = (array) => {
    console.log(array)
  }
  zql.rowListeners.push(addTableRow);
  await zql.loadFile(getFile(DB_FILE))
  console.log("Loaded");
});

describe('Compare ZQL to SQL', () => {
  test('select all', async () => {
    await zql.exec('select * from example;');
    const query = sql.prepare('SELECT * FROM example');
    const sqlResults = query.all();
    // TODO: write helper function to actually compare and get results from ZQL
    expect(sqlResults.length).toBe(3);
  });
});

