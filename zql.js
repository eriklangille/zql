// each page of memory is 64 KiB for wasm
// types: i32, i64, f32, f64, v128?
// Uint8Array is a view of the memory, it doesn't allocate memory
// The memory is allocated by the FileReader and the malloc function

const BUFFER_SIZE = 1024 * 512; // 512 KiB
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
    * Called from WASM. Writes from the dbFile at index readPointer of length bytes to the WASM memory buffer at index writePointer 
    * @param {number} writePointer the address to write the memory
    * @param {number} readPointer the address to read the memory from the file
    * @param {number} length the number of bytes to read
    */
    const readBuffer = (writePointer, readPointer, length) => {
      if (this.#dbFile == null || this.#instance == null) return;
      console.log('[readBuffer] writePointer:', writePointer, 'readPointer:', readPointer, 'length:', length);
      const memory = new Uint8Array(this.#instance.exports.memory.buffer, writePointer, length);
      const fileData = new Uint8Array(this.#dbFile);
      console.log('Reading buffer from file');
      memory.set(fileData.slice(readPointer, readPointer + length));
    }

    this.#env = {
      print: print,
      readBuffer: readBuffer,
      renderRow: renderRow,
    }
  }

  async init() {
    const results = await (typeof process === 'object'
      ? WebAssembly.instantiate(await import('fs/promises').then(async (fs) => {
          const path = await import('path');
          return fs.readFile(path.join(process.cwd(), './zql.wasm'));
        }), { env: this.#env })
      : WebAssembly.instantiateStreaming(fetch('./zql.wasm'), { env: this.#env })
    );

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
    runStatementWithFile(this.#dbMemoryAddress, BUFFER_SIZE);
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

export default async function loadZQL() {
  const zql = new ZqlDb();
  await zql.init();
  return zql;
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

