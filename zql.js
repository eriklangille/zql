// each page of memory is 64 KiB for wasm
// types: i32, i64, f32, f64, v128?
// Uint8Array is a view of the memory, it doesn't allocate memory
// The memory is allocated by the FileReader and the malloc function

const BUFFER_SIZE = 1024 * 64; // 64 KiB
const SQLITE_HEADER_SIZE = 100;
const MAX_STATEMENT_LEN = 512;

// TODO: remove below. But it's an example on JSDoc Objects
/**
 * @typedef {Object} DatabaseFile
 * @property {ArrayBuffer} content - The content of the file.
 * @property {boolean} isFetchResult - Whether the file was fetched from a server.
 */

class ZqlDb {
  rowListeners;
  #instance;
  #dbMemoryAddress;
  #dbFile;
  #env;

  /**
  * Creates a new ZqlDb instance.
  * @param {WebAssembly.Instance} instance - The WebAssembly instance.
  */
  constructor () {
    this.rowListeners = [];
    this.#instance = null;
    this.#dbMemoryAddress = null;
    this.#dbFile = null;

    /**
    * Prints a string to the console from WebAssembly memory.
    * @param {number} arrayPointer - The pointer to the start of the string in WebAssembly memory.
    * @param {number} length - The length of the string to print.
    */
    const print = (arrayPointer, length) => {
      const memory = new Uint8Array(this.#instance.exports.memory.buffer, arrayPointer, length);
      const string = new TextDecoder().decode(memory);
      console.log(string);
    }

    /**
    * Adds a new row to the table with the given array of values.
    * @param {Array} array - An array of values to be added as cells in the new row.
    */
    const addTableRow = (array) => {
      const tableBody = document.querySelector("#myTable tbody");
      const tr = document.createElement("tr");
      array.forEach(value => {
        const td = document.createElement("td");
        td.textContent = value;
        tr.appendChild(td)
      });
      tableBody.appendChild(tr);
    }
    this.rowListeners.push(addTableRow);

    /**
    * Prints a string to the console from WebAssembly memory.
    * @param {number} arrayPointer - The pointer to the start of the string in WebAssembly memory.
    * @param {number} length - The length of the string to print.
    */
    const renderRow = (arrayPointer, length) => {
      const memory = new Uint8Array(this.#instance.exports.memory.buffer, arrayPointer, length);
      const dataView = new DataView(this.#instance.exports.memory.buffer);
      const colCount = dataView.getUint32(arrayPointer, true)
      let i = 4;
      let row = [];
      let colIndex = 0;
      while (colIndex <= colCount && i < length) {
        const colType = dataView.getUint32(i + arrayPointer, true);
        i += 4;
        switch (colType) {
          case 0: // Null value
            row.push(null);
            break;
          case 1: // Integer
            const intValue = dataView.getBigInt64(i + arrayPointer, true);
            row.push(intValue);
            i += 8;
            break;
          case 2: // Float
            row.push(dataView.getFloat64(i + arrayPointer, true));
            i += 8;
            break;
          case 3: // string
            const str_len = dataView.getUint32(i + arrayPointer, true);
            i += 4;
            const memSlice = memory.slice(i, i + str_len);
            const str = new TextDecoder().decode(memSlice);
            row.push(str);
            i += str_len;
            break;
          case 4: // binary
            const byte_len = dataView.getUint32(i, true);
            i += 4;
            row.push(memory.buffer.slice(i + arrayPointer, i + arrayPointer + byte_len));
            i += len;
            break;
          default:
            console.error("Invalid colType: " + colType);
            break;
        }
        colIndex += 1;
      }
      this.rowListeners.forEach(listener => {
        try {
          listener(row)
        } catch (error) {
          console.error(error);
        }
      });
    }

    /**
    * Listens for a file input change event and resolves with the file data as a Uint8Array.
    * @param {number} writePointer the address to write the memory
    * @param {number} readPointer the address to read the memory from the file
    * @param {number} length the number of bytes to read
    */
    const readBuffer = (writePointer, readPointer, length) => {
      if (this.#dbFile == null || this.#instance == null) return;
      console.log('writePointer:', writePointer, 'readPointer:', readPointer, 'length:', length);
      const memory = new Uint8Array(this.#instance.exports.memory.buffer, writePointer, length);
      const fileData = new Uint8Array(this.#dbFile);
      console.log('Reading buffer from file:', fileData);
      memory.set(fileData.slice(readPointer, readPointer + length));
    }

    this.#env = {
      print: print,
      readBuffer: readBuffer,
      renderRow: renderRow,
    }
  }

  async init() {
    const results = await WebAssembly.instantiateStreaming(fetch('zql.wasm'), {
      env: this.#env,
    })

    console.log('WASM Loaded, instance:', results.instance);
    this.#instance = results.instance;
    this.#dbMemoryAddress = results.instance.exports.malloc(BUFFER_SIZE);
  }

  /**
  * Executes an SQL statement.
  * @param {string} sqlStatement - The SQL statement to execute.
  * @returns {Promise<void>}
  */
  async exec(sqlStatement) {
    const { runStatementWithFile, getStatementAddr } = this.#instance.exports;

    const encoder = new TextEncoder();
    const sqlArray = encoder.encode(sqlStatement);
    const sqlArrayTerminator = new Uint8Array(sqlArray.length + 1);
    sqlArrayTerminator.set(sqlArray);
    sqlArrayTerminator[sqlArray.length] = 0;
    const sqlAddress = getStatementAddr();

    const memory = new Uint8Array(this.#instance.exports.memory.buffer);
    memory.set(sqlArrayTerminator.slice(0, MAX_STATEMENT_LEN), sqlAddress);
    runStatementWithFile(this.#dbMemoryAddress, SQLITE_HEADER_SIZE);
  }

  /**
  * Loads a database file into memory.
  * @param {Promise<DatabaseFile>} filePromise - A promise that resolves to the database file.
  * @returns {Promise<void>}
  */
  async loadFile(filePromise) {
    const dbFileBuffer = await filePromise;
    const dbFile = new Uint8Array(dbFileBuffer);
    this.#dbFile = dbFile;
    console.log(dbFile);

    const memory = new Uint8Array(this.#instance.exports.memory.buffer);
    memory.set(dbFile.slice(0, SQLITE_HEADER_SIZE), this.#dbMemoryAddress);
    console.log("DB loaded");
  }
}

async function loadZQL() {
  const zql = new ZqlDb();
  await zql.init();
  return zql;
}

function clearTable() {
  const tableBody = document.querySelector("#myTable tbody");
  tableBody.innerHTML = '';
}

/**
 * Listens for a file input change event and resolves with the file data as a Uint8Array.
 * @returns {Promise<DatabaseFile>} A promise that resolves with the file data as a Uint8Array.
 */
async function listenForInputFile() {
  return new Promise((resolve, reject) => {
    document.getElementById('fileInput').addEventListener('change', (e) => {
      const file = e.target.files[0];
      const reader = new FileReader();
      reader.onload = (e) => {
        const readerResult = e.target.result;
        databaseFile = readerResult;
        resolve(databaseFile);
      };
      reader.onerror = (e) => {
        reject(e);
      };
      reader.readAsArrayBuffer(file);
    });
  });
}

async function getFile(name) {
  let response = await fetch(name);

  if (!response.ok) {
    throw new Error(`HTTP error: ${response.status}`);
  }

  const arrayBuffer = await response.arrayBuffer();
  databaseFile = arrayBuffer;
  return databaseFile;
}


function getSQLInput() {
    const inputSqlStatement = document.getElementById('statementInput');
    const sqlStatement = inputSqlStatement.value;
    console.log(`statementInput: ${sqlStatement}`);
    return sqlStatement;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

async function runTests(zql) {
  rows = [];
  const testListener = (row) => {
    rows.push(row);
  };
  zql.rowListeners.push(testListener);
  rows.splice(0, rows.length); // clear array
  await zql.exec("select * from example");
  assert(rows.length == 3, "row length");
  assert(rows[0][1] == "Alice", "row name");
  console.log("tests passed!")
}

function main() {
  loadZQL().then(async (zql) => {

    const button = document.getElementById('test-button');
    button.addEventListener('click', async () => {
        await zql.loadFile(getFile('test.db'));
        runTests(zql);
    });

    await zql.loadFile(listenForInputFile()).then(() => zql.exec(getSQLInput()));
  });
}

main();
