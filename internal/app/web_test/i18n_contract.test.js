const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const webRoot = path.join(__dirname, '..', 'web');
const i18nPath = path.join(webRoot, 'js', 'i18n.js');

function loadTranslations() {
  const app = {
    state: {},
    el: {},
    $() { return null; }
  };
  const storage = new Map();
  const context = vm.createContext({
    window: { VeerApp: app, matchMedia: () => null },
    document: {
      documentElement: { dataset: {}, style: {} },
      querySelectorAll() { return []; },
      title: ''
    },
    localStorage: {
      getItem(key) { return storage.has(key) ? storage.get(key) : null; },
      setItem(key, value) { storage.set(key, String(value)); }
    },
    navigator: { languages: ['zh-CN'], language: 'zh-CN' },
    clearInterval() {},
    Node: function Node() {}
  });
  vm.runInContext(fs.readFileSync(i18nPath, 'utf8'), context, { filename: i18nPath });
  return app.translations;
}

function webSourceFiles(root) {
  const out = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) out.push(...webSourceFiles(fullPath));
    else if (entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.html'))) out.push(fullPath);
  }
  return out;
}

function staticTranslationReferences() {
  const references = new Map();
  const remember = (key, filePath) => {
    if (!key || key.endsWith('.')) return;
    if (!references.has(key)) references.set(key, new Set());
    references.get(key).add(path.relative(webRoot, filePath).replaceAll('\\', '/'));
  };

  for (const filePath of webSourceFiles(webRoot)) {
    const source = fs.readFileSync(filePath, 'utf8');
    for (const match of source.matchAll(/app\.t\(\s*(['"])([^'"]+)\1/g)) remember(match[2], filePath);
    for (const match of source.matchAll(/\bdata-i18n(?:-[a-z-]+)?=(['"])([^'"]+)\1/g)) remember(match[2], filePath);
  }
  return references;
}

test('WebUI locale dictionaries expose the same unique keys', () => {
  const translations = loadTranslations();
  const locales = Object.keys(translations).sort();
  assert.deepEqual(locales, ['en-US', 'zh-CN']);

  const expected = Object.keys(translations['zh-CN']).sort();
  assert.deepEqual(Object.keys(translations['en-US']).sort(), expected);

  const source = fs.readFileSync(i18nPath, 'utf8');
  const definitions = new Map();
  for (const match of source.matchAll(/^\s*'([^']+\.[^']+)':/gm)) {
    definitions.set(match[1], (definitions.get(match[1]) || 0) + 1);
  }
  const duplicateOrMissing = [...definitions]
    .filter(([, count]) => count !== locales.length)
    .map(([key, count]) => `${key} (${count}/${locales.length})`);
  assert.deepEqual(duplicateOrMissing, []);
});

test('WebUI static translation references exist in every locale', () => {
  const translations = loadTranslations();
  const references = staticTranslationReferences();
  const missing = [];
  for (const [key, files] of references) {
    for (const [locale, dictionary] of Object.entries(translations)) {
      if (!Object.prototype.hasOwnProperty.call(dictionary, key)) {
        missing.push(`${locale}: ${key} (${[...files].join(', ')})`);
      }
    }
  }
  assert.deepEqual(missing.sort(), []);
});
