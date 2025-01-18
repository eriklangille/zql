import { promises as fs } from 'fs';
import { DatabaseSync } from 'node:sqlite';
import loadZQL from '../zql.js';

const SMALL_DB_FILE = './test.db';
const MED_DB_FILE = './med.db';
const BACKUP_DB_FILE = './backup.db';
const BIG_DB_FILE = './example.db';
let zql;
let zqlResult = [];
let sqlResult = [];
let sql;

async function getFile(name) {
  try {
    const data = await fs.readFile(name);
    return data.buffer;
  } catch (error) {
    throw new Error(`File read error: ${error.message}`);
  }
}

async function compareInternal(query) {
  const sqlQuery = sql.prepare(query);
  sqlResult = sqlQuery.all();
  await zql.exec(query);
  const expected = []
  const actual = []
  for (let i = 0; i < sqlResult.length; i++) {
    const actual_item = [];
    const expected_item = [];
    const obj = sqlResult[i];
    let j = 0;
    for (const key in obj) {
      const sqlItem = obj[key];
      expected_item.push(sqlItem);
      if (zqlResult.length <= i) continue;
      let zqlItem = zqlResult[i][j];
      if (typeof zqlItem == 'bigint') {
        zqlItem = Number(zqlItem);
      }
      actual_item.push(zqlItem);
      j++;
    }
    actual.push(actual_item);
    expected.push(expected_item);
  }
  expect(actual).toStrictEqual(expected);
  // clear the array
  zqlResult = [];
}

function compare(query) {
  test(query, async () => {
    await compareInternal(query);
  });
}

function compareOnly(query) {
  test.only(query, async () => {
    await compareInternal(query);
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

async function describeDb(dbFile, callback) {
  describe(dbFile, () => {
    beforeAll(async () => {
      await load(dbFile);
    });
    beforeEach(() => {
      // Clear any lingering results from past failures
      sqlResult = [];
      zqlResult = [];
    });
    callback();
  });
}

describeDb(SMALL_DB_FILE, () => {
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

describeDb(MED_DB_FILE, () => {
  compare("select * from t1;");
  compare("select * from t2;");
  compare("select * from t3;");
  compare("select * from t1 where id > 1;");
  compare("select * from t1 where id >= 1;");
  compare("select * from t1 where age >= 19;");
  compare("select * from t1 where id < 4;");
  compare("select * from t1 where name like 'a%' or name = 'Louis' or name = 'Paul';");
  compare("select name from t1 where name <> 'Paul';");
  compare("select name from t1 where name != 'Paul';");
  compare(`select "name" from t1 where name != 'Paul';`);
  compare("select * from t2 where id = t1_id;");
  compare("select * from t2 where id != t1_id;");
  compare("select * from t1 where id > 1 and id < 4;");
  compare("select * from t1 where id < 2 or id > 4;");

  // TODO: compare function that is correct if right records are returned, even if in different order
  // This comparison in SQLite first outputs the records with id > 2, then goes back and outputs 1 and 2
  // compare("select * from t1 where id > 2 or id < 4;");

  // Alias
  compare("select name as n, age as a from t1 where 20 < a and n != 'Paul';");
  compare("select name as 'n ', age as a from t1 where 20 < a and 'n ' != 'Paul';");
  compare(`select name as "n ", age as a from t1 where 20 < a and "n " != 'Paul';`);

  // Left side constant / Right side column comparison
  compare("select * from t1 where 1 < id;");
  compare("select * from t1 where 1 <= id;");
  compare("select * from t1 where 19 <= age;");

  // Compare constants
  compare("select * from t1 where 1 != 1;");
  compare("select * from t1 where 1 == 1;");
  compare("select * from t1 where 1 > 1;");
  compare("select * from t1 where 1 < 1;");
  compare("select * from t1 where 1 >= 1;");
  compare("select * from t1 where 1 <= 1;");

  // Column evaluation
  compare("select * from t1 where age;");
  compare("select * from t1 where name;");
  compare("select * from t1 where name or age;");
  compare("select * from t1 where name or 19 <= age;");

  // Column ordering
  compare("select age, name from t1;");
  compare("select name, age from t1;");

  // And Or Tests
  compare("select * from t1 where name like '%o%' and name = 'Louis' or name = 'Paul';");
  compare("select * from t1 where id = 1 and name = 'Paul' or age = 21 and name = 'Ryan' or id = 3 and name = 'Michael' and age = 26;");
  compare("select * from t1 where name <> 'Paul' and name <> 'Ryan' or age = 21 and name = 'Ryan' or id = 3 and name = 'Michael' and age = 26;");
  compare("select * from t1 where id > 4 or age = 21 and name = 'Ryan' or id = 3 and name = 'Michael' and age = 26;");

  // Brackets
  compare("select * from t1 where (id > 4) or (age = 21) and (name = 'Ryan') or (id = 3 and name = 'Michael') and age = 26;");
  compare("select * from t1 where id = 1 and name = 'Paul' or age = 21 and (name = 'Ryan' or id = 3) and name = 'Michael' and age = 26;");
  compare("select * from t1 where (id = 1 and name = 'Paul') or age = 21 and (name = 'Ryan' or id = 3) and (name = 'Michael' and age = 26);");
  compare("select * from t1 where id = 1 and name = 'Paul' or age = 21 and ((name = 'Ryan' or id = 3) and name = 'Michael') and age = 26;");
  compare("select *, name as n from t1 where (id <= 100 or id > 5000) and n like 'p%';");

  compare("select * from t1 where age < 18 or name like '%a%';");
  compare("select * from t1 where age <= 18 or name like '%a%';");
  compare("select * from t1 where name like '_%';");
  compare("select * from t1 where name like '%_';");
  compare("select * from t1 where name like '%___';");
});

describeDb(BACKUP_DB_FILE, () => {
  compare("select * from test;");
});

describeDb(BIG_DB_FILE, () => {
  compare("select * from records where name like '%a';");
  compare("select * from records where name like '%a%a';");
  compare("select * from records where name like 'a%a';");
  compare("select * from records where name like 'a%b';");
  compare("select * from records where name like 'a%';");
  compare("select * from records where name like 'simfyvo__a';");
});

