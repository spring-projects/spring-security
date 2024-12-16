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

import "./bootstrap.js";
import abortController from "../lib/abort-controller.js";
import { expect } from "chai";

describe("abort-controller", () => {
  describe("newSignal", () => {
    it("returns an AbortSignal", () => {
      const signal = abortController.newSignal();

      expect(signal).to.be.instanceof(AbortSignal);
      expect(signal.aborted).to.be.false;
    });

    it("returns a new signal every time", () => {
      const initialSignal = abortController.newSignal();

      const newSignal = abortController.newSignal();

      expect(initialSignal).to.not.equal(newSignal);
    });

    it("aborts the existing signal", () => {
      const signal = abortController.newSignal();

      abortController.newSignal();

      expect(signal.aborted).to.be.true;
      expect(signal.reason).to.equal("Initiating new WebAuthN ceremony, cancelling current ceremony");
    });
  });
});
