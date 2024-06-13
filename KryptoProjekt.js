const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const readline = require("readline");
const fs = require("fs");
const createHash = require("sha.js");
const path = require("path");

if (isMainThread) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  // Ziskani vstupnich dat od uzivatele
  rl.question("Zadej SHA0 hash na prolomeni:", (targetHash) => {
    rl.question(
      "Zadej delku hesla (Enter pokud neni znama): ",
      (lengthInput) => {
        const length = lengthInput ? parseInt(lengthInput) : undefined;
        rl.question("Zadej salt (Enter pokud neni znam): ", (salt) => {
          rl.question(
            "Zadej pocet vyuzitelnych vlaken procesoru (jinak bude pouzito 1):",
            (numThreadsInput) => {
              rl.close();

              // Zpracovani slovniku pred startem brute force
              processDictionaries(targetHash, salt, () => {
                // Zacne prolomovani v uvedenymi daty
                startBruteForce(targetHash, length, salt, numThreadsInput);
              });
            }
          );
        });
      }
    );
  });
  // Funkce pro zpracovani slovniku, pri shode ukonci program, jiinak zacne brute force
  function processDictionaries(targetHash, salt, callback) {
    const files = ["./passwordLists/en.txt", "./passwordLists/cs.txt", "./passwordLists/sk.txt"];
    let found = false;

    // Funkce pro vytvoreni SHA0 hashe
    function sha0(value) {
      const hash = createHash("sha").update(value, "utf8");
      if (salt) {
        hash.update(salt, "utf8");
      }
      return hash.digest("hex");
    }

    function checkFile(fileIndex) {
      if (fileIndex >= files.length) {
        // Pokud dojdou slovniky, zacne brute force
        return callback();
      }

      const filePath = files[fileIndex];
      const readStream = fs.createReadStream(filePath, { encoding: 'utf8' });

      // Prochazi slovnik po radku a hleda shodu
      readStream.on('data', (chunk) => {
        const passwords = chunk.split('\n');
        for (const password of passwords) {
          if (sha0(password) === targetHash) {
            console.log(`Heslo nalezeno ve slovniku: ${password}`);
            found = true;
            readStream.close();
            break;
          }
        }
      });

      // Pokud byl soubor precten bez shody, zkontroluje dalsi soubor,
      readStream.on('close', () => {
        if (!found) {
          checkFile(fileIndex + 1);
        }
      });

      readStream.on('error', (err) => {
        console.error(`Chyba pri cteni souboru: ${filePath}:`, err);
        checkFile(fileIndex + 1);
      });
    }
    // Spusti kontrolu prvniho souboru
    checkFile(0);
  }

  // Funkce pro zahajeni brute force
  function startBruteForce(targetHash, length, salt, threads) {
    // Znaky pro generovani hesel (je mozne upravit podle potreby)
    const CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789";
    // Maximalni delka hesla (lze upravit, ale bylo by to casove narocne)
    const MAX_LENGTH = 8;
    const numThreads = parseInt(threads) || 1;

    // Vytvori vlakna podle poctu od uzivatele a preda jim potrebna data
    const workers = [];
    for (let i = 0; i < numThreads; i++) {
      const worker = new Worker(__filename, {
        workerData: {
          targetHash,
          CHARSET,
          MAX_LENGTH,
          length,
          salt,
          threadId: i,
          numThreads,
        },
      });
      workers.push(worker);

      // Ukonci vsechny procesy pokud byl nalezen vysledek
      worker.on("message", (result) => {
        if (result.found) {
          console.log(`Password found: ${result.password}`);
          workers.forEach((w) => w.terminate());
        }
      });
    }
  }
} else {
  // Funkce spustena v kazdem vlakne, ktera provadi brute force
  const { targetHash, CHARSET, MAX_LENGTH, length, salt, threadId, numThreads } =
    workerData;

  // Funkce pro vytvoreni SHA0 hashe
  function sha0(value) {
    const hash = createHash("sha").update(value, "utf8");
    if (salt) {
      // Pokud je zadan salt, pouzije se pro vytvoreni hashe
      hash.update(salt, "utf8");
    }
    return hash.digest("hex");
  }

  // Generator kombinaci hesel
  function* generateCombinations(CHARSET, length) {
    const maxCombinations = Math.pow(CHARSET.length, length);
    for (let i = threadId; i < maxCombinations; i += numThreads) {
      let combination = "";
      let n = i;
      for (let j = 0; j < length; j++) {
        combination = CHARSET[n % CHARSET.length] + combination;
        n = Math.floor(n / CHARSET.length);
      }
      yield combination;
    }
  }

  // Pokud uzivatel nezadal delku hesla, zkusi vsechny hesla o delce 1-8 (lze upravit, ale bylo by to casove narocne)
  if (!length) {
    for (let length = 1; length <= MAX_LENGTH; length++) {
      for (const combination of generateCombinations(CHARSET, length)) {
        if (sha0(combination) === targetHash) {
          parentPort.postMessage({ found: true, password: combination });
          return;
        }
      }
    }
  }
  // Pokud uzivatel zadal delku hesla, zkusi vsechny hesla dane delky
  else {
    for (const combination of generateCombinations(CHARSET, length)) {
      if (sha0(combination) === targetHash) {
        parentPort.postMessage({ found: true, password: combination });
        return;
      }
    }
  }
  parentPort.postMessage({ found: false });
}
