// each page of memory is 64 KiB for wasm
// types: i32, i64, f32, f64, v128?
// Uint8Array is a view of the memory, it doesn't allocate memory
// The memory is allocated by the FileReader and the malloc function

const BUFFER_SIZE = 1024 * 64; // 64 KiB
const SQLITE_HEADER_SIZE = 100;
const MAX_STATEMENT_LEN = 512;
let instance = null;
let fileReader = null;

function print(arrayPointer, length) {
  const memory = new Uint8Array(instance.exports.memory.buffer, arrayPointer, length);
  const string = new TextDecoder().decode(memory);
  console.log(string);
}

function readBuffer(writePointer, readPointer, length) {
  if (fileReader == null || instance == null) return;
  console.log('writePointer:', writePointer, 'readPointer:', readPointer, 'length:', length);
  const memory = new Uint8Array(instance.exports.memory.buffer, writePointer, length);
  const fileData = new Uint8Array(fileReader.result);
  console.log('Reading buffer from file:', fileData);
  memory.set(fileData.slice(readPointer, readPointer + length));
}

/**
 * Listens for a file input change event and resolves with the file data as a Uint8Array.
 * @returns {Promise<FileReader>} A promise that resolves with the file data as a Uint8Array.
 */
async function listenForFile() {
  return new Promise((resolve, reject) => {
    document.getElementById('fileInput').addEventListener('change', (e) => {
      const file = e.target.files[0];
      const reader = new FileReader();
      reader.onload = (e) => {
        const readerResult = e.target;
        fileReader = readerResult;
        resolve(readerResult);
      };
      reader.onerror = (e) => {
        reject(e);
      };
      reader.readAsArrayBuffer(file);
    });
  });
}

async function handle(instance) {
  console.log('WASM Loaded, instance:', instance);
  const { malloc, runStatementWithFile, getStatementAddr } = instance.exports;
  const dbFileReader = await listenForFile();
  const dbFile = new Uint8Array(dbFileReader.result);
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
  WebAssembly.instantiateStreaming(fetch('zql.wasm'), {
    env: {
      print: print,
      readBuffer: readBuffer,
    }
  }).then(results => {
    instance = results.instance;
    console.log(instance.exports);
    handle(instance);
  });
}

main();
