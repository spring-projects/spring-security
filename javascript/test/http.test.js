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

import http from "../lib/http.js";
import { expect } from "chai";
import { fake, assert } from "sinon";

describe("http", () => {
  beforeEach(() => {
    global.fetch = fake.resolves({ ok: true });
  });

  afterEach(() => {
    delete global.fetch;
  });

  describe("post", () => {
    it("calls fetch with headers", async () => {
      const url = "https://example.com/some/path";
      const headers = { "x-custom": "some-value" };

      const resp = await http.post(url, headers);

      expect(resp.ok).to.be.true;
      assert.calledOnceWithExactly(global.fetch, url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...headers,
        },
      });
    });

    it("sends the body as a JSON string", async () => {
      const body = { foo: "bar", baz: 42 };
      const url = "https://example.com/some/path";

      const resp = await http.post(url, {}, body);

      expect(resp.ok).to.be.true;
      assert.calledOnceWithExactly(global.fetch, url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: `{"foo":"bar","baz":42}`,
      });
    });
  });
});
