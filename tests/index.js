import { promises as fs } from 'fs';
import { DatabaseSync } from 'node:sqlite';
import loadZQL from '../zql.js';

async function getFile(name) {
  try {
    const data = await fs.readFile(name);
    return data.buffer;
  } catch (error) {
    throw new Error(`File read error: ${error.message}`);
  }
}

console.log("Loading SQLite");
const sql = new DatabaseSync('./test.db');
const query = sql.prepare('SELECT * FROM example');

console.log(query.all());

console.log("Loading ZQL");

loadZQL().then(async (zql) => {
    /**
    * Adds a new row to the table with the given array of values.
    * @param {Array} array - An array of values to be added as cells in the new row.
    */
    const addTableRow = (array) => {
      console.log(array)
    }
    zql.rowListeners.push(addTableRow);

    await zql.loadFile(getFile('./test.db'));
    await zql.exec('select * from example;');
});

console.log("Loaded");
