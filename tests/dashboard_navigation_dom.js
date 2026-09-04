"use strict";

const assert = require("assert");
const fs = require("fs");
const vm = require("vm");
const path = require("path");

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.textContent = "";
    this.attributes = {};
  }
  append(...children) { this.children.push(...children); }
  set href(value) { this.attributes.href = value; }
  get href() { return this.attributes.href; }
  set rel(value) { this.attributes.rel = value; }
}

globalThis.__FLOP_DASHBOARD_TEST_MODE__ = true;
globalThis.document = {createElement: tag => new Element(tag)};
const source = fs.readFileSync(path.join(__dirname, "..", "dashboard.js"), "utf8");
vm.runInThisContext(source, {filename: "dashboard.js"});

const api = globalThis.__FLOP_DASHBOARD_TEST_API__;
const remote = new Element("div");
api.appendSafeNavigation(remote, "https://flop.finance/", "remote text", undefined);
assert.strictEqual(remote.children[0].tagName, "SPAN");
assert.strictEqual(remote.children[0].href, undefined);

const reviewed = new Element("div");
api.appendSafeNavigation(reviewed, "https://flop.finance/", "official", "FLOP_FINANCE");
assert.strictEqual(reviewed.children[0].tagName, "A");
assert.strictEqual(reviewed.children[0].href, "https://flop.finance/");

for (const value of ["javascript:alert(1)", "file:///tmp/key", "data:text/html,bad",
                     "http://localhost/", "https://127.0.0.1/"]) {
  const parent = new Element("div");
  api.appendSafeNavigation(parent, value, "unsafe", "FLOP_FINANCE");
  assert.strictEqual(parent.children[0].href, undefined);
}

process.stdout.write("DASHBOARD_DOM_SAFETY_PASS\n");
