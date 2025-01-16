import loadZQL, { getFileFromUrl } from './zql.js';

const DEFAULT_DB_FILE = './med.db';

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

document.getElementById('query-button').addEventListener('click', async () => {
  const sqlStatement = getSQLInput();
  if (window.zql == null) return;
  clearTable();
  await window.zql.exec(sqlStatement);
});

function clearTable() {
  const tableBody = document.querySelector("#zqlTable tbody");
  tableBody.innerHTML = '';
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
      const tableBody = document.querySelector("#zqlTable tbody");
      const tr = document.createElement("tr");
      array.forEach(value => {
        const td = document.createElement("td");
        td.textContent = value;
        tr.appendChild(td)
      });
      tableBody.appendChild(tr);
    }
    zql.rowListeners.push(addTableRow);
    window.zql = zql;

    await zql.loadFile(getFileFromUrl(DEFAULT_DB_FILE))
    await zql.loadFile(listenForInputFile());
});

