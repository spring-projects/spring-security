/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

"use strict";

import { expect } from "chai";
import base64url from "../lib/base64url.js";

describe("base64url", () => {
  before(() => {
    // Emulate the atob / btoa base64 encoding/decoding from the browser
    global.window = {
      btoa: (str) => Buffer.from(str, "binary").toString("base64"),
      atob: (b64) => Buffer.from(b64, "base64").toString("binary"),
    };
  });

  after(() => {
    // Reset window object
    global.window = {};
  });

  it("decodes", () => {
    // "Zm9vYmFy" is "foobar" in base 64, i.e. f:102 o:111 o:111 b:98 a:97 r:114
    const decoded = base64url.decode("Zm9vYmFy");

    expect(new Uint8Array(decoded)).to.be.deep.equal(new Uint8Array([102, 111, 111, 98, 97, 114]));
  });

  it("decodes special characters", () => {
    // Wrap the decode function for easy testing
    const decode = (str) => {
      const decoded = new Uint8Array(base64url.decode(str));
      return Array.from(decoded);
    };

    // "Pz8/" is "???" in base64, i.e. ?:63 three times
    expect(decode("Pz8/")).to.be.deep.equal(decode("Pz8_"));
    expect(decode("Pz8_")).to.be.deep.equal([63, 63, 63]);
    // "Pj4+" is ">>>" in base64, ie >:62 three times
    expect(decode("Pj4+")).to.be.deep.equal(decode("Pj4-"));
    expect(decode("Pj4-")).to.be.deep.equal([62, 62, 62]);
  });

  it("encodes", () => {
    const encoded = base64url.encode(Buffer.from("foobar"));

    expect(encoded).to.be.equal("Zm9vYmFy");
  });

  it("encodes special +/ characters", () => {
    const encode = (str) => base64url.encode(Buffer.from(str));

    expect(encode("???")).to.be.equal("Pz8_");
    expect(encode(">>>")).to.be.equal("Pj4-");
  });

  it("is stable", () => {
    const base = "tyRDnKxdj7uWOT5jrchXu54lo6nf3bWOUvMQnGOXk7g";

    expect(base64url.encode(base64url.decode(base))).to.be.equal(base);
  });
});
