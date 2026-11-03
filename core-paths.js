'use strict';
const os = require('os');
const path = require('path');

function resolvePaths(env = process.env) {
  const home = env.HOME || os.homedir();
  const configDir = env.ORKARDCH_CONFIG_DIR || path.join(env.XDG_CONFIG_HOME || path.join(home, '.config'), 'orkardch');
  const dataDir = env.ORKARDCH_DATA_DIR || path.join(env.XDG_DATA_HOME || path.join(home, '.local', 'share'), 'orkardch');
  return {
    home,
    configDir,
    dataDir,
    configFile: path.join(configDir, 'config.json'),
    tunnelrFile: path.join(configDir, 'tunnelr.json'),
    stateFile: path.join(dataDir, 'state.json'),
    investigationsDir: path.join(dataDir, 'investigations'),
    cacheDir: path.join(dataDir, 'cache'),
    logDir: path.join(dataDir, 'logs'),
    runtimeDir: path.join(dataDir, 'runtime'),
    baselinesFile: path.join(dataDir, 'baselines.json'),
    defaultOutputDir: env.ORKARDCH_OUTPUT_DIR || path.join(home, 'orkardch-output'),
    projectDir: __dirname,
  };
}

function isTermux(env = process.env) {
  return Boolean(env.TERMUX_VERSION) || /com\.termux/.test(env.PREFIX || '');
}

module.exports = { resolvePaths, isTermux };
