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
    this.listeners = {};
  }
  append(...children) { this.children.push(...children); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  set href(value) { this.attributes.href = value; }
  get href() { return this.attributes.href; }
  set rel(value) { this.attributes.rel = value; }
  set onclick(value) { this.attributes.onclick = value; }
  get onclick() { return this.attributes.onclick; }
  set innerHTML(_value) { throw new Error("remote HTML was interpreted"); }
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
assert.strictEqual(remote.children[0].onclick, undefined);
assert.deepStrictEqual(remote.children[0].listeners, {});

const reviewed = new Element("div");
api.appendSafeNavigation(reviewed, "https://flop.finance/", "official", "FLOP_FINANCE");
assert.strictEqual(reviewed.children[0].tagName, "A");
assert.strictEqual(reviewed.children[0].href, "https://flop.finance/");
assert.strictEqual(reviewed.children[0].onclick, undefined);
assert.deepStrictEqual(reviewed.children[0].listeners, {});

const hostileHtml = '<img src=x onerror="navigate()"><a href="javascript:navigate()">x</a><script>navigate()</script>';
const htmlParent = new Element("div");
api.appendSafeNavigation(htmlParent, "https://attacker.invalid/", hostileHtml, undefined);
assert.strictEqual(htmlParent.children.length, 1);
assert.strictEqual(htmlParent.children[0].tagName, "SPAN");
assert.strictEqual(htmlParent.children[0].textContent, hostileHtml);
assert.strictEqual(htmlParent.children[0].children.length, 0);
assert.strictEqual(htmlParent.children[0].href, undefined);
assert.strictEqual(htmlParent.children[0].onclick, undefined);
assert.deepStrictEqual(htmlParent.children[0].listeners, {});

for (const value of ["javascript:alert(1)", "file:///tmp/key", "data:text/html,bad",
                     "http://localhost/", "https://127.0.0.1/"]) {
  const parent = new Element("div");
  api.appendSafeNavigation(parent, value, "unsafe", "FLOP_FINANCE");
  assert.strictEqual(parent.children[0].href, undefined);
  assert.strictEqual(parent.children[0].onclick, undefined);
  assert.deepStrictEqual(parent.children[0].listeners, {});
}

process.stdout.write("DASHBOARD_DOM_SAFETY_PASS\n");
