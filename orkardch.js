#!/usr/bin/env node
'use strict';
// Orkardch entry point. All real work lives in cli-main.js.
const { run } = require('./cli-main');
run(process.argv.slice(2), process.env)
  .then((code) => { process.exitCode = code; })
  .catch((err) => {
    process.stderr.write(`Orkardch hit an unexpected problem: ${err && err.message ? err.message : err}\n`);
    process.exitCode = 1;
  });
