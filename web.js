import loadZQL from './zql.js';

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
        resolve(readerResult);
      };
      reader.onerror = (e) => {
        reject(e);
      };
      reader.readAsArrayBuffer(file);
    });
  });
}

function clearTable() {
  const tableBody = document.querySelector("#myTable tbody");
  tableBody.innerHTML = '';
}

async function test(zql) {
    const button = document.getElementById('test-button');
    button.addEventListener('click', async () => {
        await zql.loadFile(getFile('test.db'));
        runTests(zql);
    });
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

function getSQLInput() {
    const inputSqlStatement = document.getElementById('statementInput');
    const sqlStatement = inputSqlStatement.value;
    console.log(`statementInput: ${sqlStatement}`);
    return sqlStatement;
}

loadZQL().then(async (zql) => {
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
    zql.rowListeners.push(addTableRow);

    await zql.loadFile(listenForInputFile());
    await zql.exec(getSQLInput());
});

