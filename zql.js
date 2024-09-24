// each page of memory is 64 KiB for wasm
// types: i32, i64, f32, f64, v128?
// Uint8Array is a view of the memory, it doesn't allocate memory
// The memory is allocated by the FileReader and the malloc function

const BUFFER_SIZE = 1024 * 64; // 64 KiB
const SQLITE_HEADER_SIZE = 100;
const MAX_STATEMENT_LEN = 512;
let instance = null;
let databaseFile = null;

/**
 * @typedef {Object} DatabaseFile
 * @property {ArrayBuffer} content - The content of the file.
 * @property {boolean} isFetchResult - Whether the file was fetched from a server.
 */

async function loadZQL() {
  function print(arrayPointer, length) {
    const memory = new Uint8Array(instance.exports.memory.buffer, arrayPointer, length);
    const string = new TextDecoder().decode(memory);
    console.log(string);
  }

  function addTableRow(array) {
    const tableBody = document.querySelector("#myTable tbody");
    const tr = document.createElement("tr");
    array.forEach(value => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td)
    });
    tableBody.appendChild(tr);
  }

  function renderRow(arrayPointer, length) {
    const memory = new Uint8Array(instance.exports.memory.buffer, arrayPointer, length);
    const dataView = new DataView(instance.exports.memory.buffer);
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
    addTableRow(row);
  }

  /**
  * Listens for a file input change event and resolves with the file data as a Uint8Array.
  * @param {number} writePointer the address to write the memory
  * @param {number} readPointer the address to read the memory from the file
  * @param {number} length the number of bytes to read
  */
  function readBuffer(writePointer, readPointer, length) {
    if (databaseFile == null || instance == null) return;
    console.log('writePointer:', writePointer, 'readPointer:', readPointer, 'length:', length);
    const memory = new Uint8Array(instance.exports.memory.buffer, writePointer, length);
    const fileData = new Uint8Array(databaseFile.content);
    console.log('Reading buffer from file:', fileData);
    memory.set(fileData.slice(readPointer, readPointer + length));
  }

  const results = await WebAssembly.instantiateStreaming(fetch('zql.wasm'), {
    env: {
      print: print,
      readBuffer: readBuffer,
      renderRow: renderRow,
    }
  })

  instance = results.instance;
  console.log(instance.exports);
  return instance;
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
        databaseFile = {
          content: readerResult,
          isFetchResult: false,
        };
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

  databaseFile = {
    content: arrayBuffer,
    isFetchResult: true,
  };

  return databaseFile;
}

async function handle(instance, filePromise) {
  console.log('WASM Loaded, instance:', instance);
  const { malloc, runStatementWithFile, getStatementAddr } = instance.exports;
  const dbFileBuffer = await filePromise;
  const dbFile = new Uint8Array(dbFileBuffer.content);
  console.log(dbFile);
  const inputSqlStatement = document.getElementById('statementInput');
  const sqlStatement = inputSqlStatement.value;
  console.log(`statementInput: ${sqlStatement}`);
  const readBuffer = malloc(BUFFER_SIZE);

  const encoder = new TextEncoder();
  const sqlArray = encoder.encode(sqlStatement);
  const sqlArrayTerminator = new Uint8Array(sqlArray.length + 1);
  sqlArrayTerminator.set(sqlArray);
  sqlArrayTerminator[sqlArray.length] = 0;
  const sqlAddress = getStatementAddr();

  const memory = new Uint8Array(instance.exports.memory.buffer);
  memory.set(dbFile.slice(0, SQLITE_HEADER_SIZE), readBuffer);
  memory.set(sqlArrayTerminator.slice(0, MAX_STATEMENT_LEN), sqlAddress);
  runStatementWithFile(readBuffer, SQLITE_HEADER_SIZE);
}

function main() {
  // loadZQL().then(instance => handle(instance, listenForInputFile()));

  // Get file using fetch
  loadZQL().then(instance => handle(instance, getFile('test.db')));
}

main();
