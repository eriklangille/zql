import { promises as fs } from 'fs';
import { DatabaseSync } from 'node:sqlite';
import loadZQL from '../zql.js';

const SMALL_DB_FILE = './test.db';
const MED_DB_FILE = './med.db';
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

function compare(query) {
  test(query, async () => {
    await zql.exec(query);
    const sqlQuery = sql.prepare(query);
    const sqlResult = sqlQuery.all();
    // console.log(zqlResult);
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
  });
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

describe('small db', () => {
  beforeAll(async () => {
    await load(SMALL_DB_FILE);
  });
  compare("select * from example;");
  compare("select id, name from example;");
  compare("select id from example;");
  compare("select name from example;");
  compare("select * from example where id = 1;");
  compare("select * from example where name = 'Alice';");
  compare("select * from example where name = 'Alice' or name = 'Bob';");
  compare("select * from example where name like 'A%'");
  compare("select * from example where name like '%l%'");
});

describe('med db', () => {
  beforeAll(async () => {
    await load(MED_DB_FILE);
  });
  compare("select * from t1;");
  compare("select * from t1 where name like 'a%' or name = 'Louis' or name = 'Paul';");
  compare("select * from t1 where age < 18 or name like '%a%';");
  compare("select * from t1 where age <= 18 or name like '%a%';");
  compare("select * from t1 where name like '_%';");
  compare("select * from t1 where name like '%_';");
  compare("select * from t1 where name like '%___';");
});

describe('backup db', () => {
  beforeAll(async () => {
    await load(BACKUP_DB_FILE);
  });
  compare("select * from test;");
});

describe('example db', () => {
  beforeAll(async () => {
    await load(BIG_DB_FILE);
  });
  compare("select * from records where name like '%a';");
  compare("select * from records where name like '%a%a';");
  compare("select * from records where name like 'a%a';");
  compare("select * from records where name like 'a%b';");
  compare("select * from records where name like 'a%';");
  compare("select * from records where name like 'simfyvo__a';");
});

