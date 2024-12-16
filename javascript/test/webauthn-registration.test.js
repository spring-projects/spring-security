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
import { expect, util, Assertion } from "chai";
import { setupRegistration } from "../lib/webauthn-registration.js";
import webauthn from "../lib/webauthn-core.js";
import { assert, fake, match, stub } from "sinon";

describe("webauthn-registration", () => {
  before(() => {
    Assertion.addProperty("visible", function () {
      const obj = util.flag(this, "object");
      new Assertion(obj).to.have.nested.property("style.display", "block");
    });
    Assertion.addProperty("hidden", function () {
      const obj = util.flag(this, "object");
      new Assertion(obj).to.have.nested.property("style.display", "none");
    });
  });

  describe("bootstrap", () => {
    let registerStub;
    let registerButton;
    let labelField;
    let errorPopup;
    let successPopup;
    let deleteForms;
    let ui;

    beforeEach(() => {
      registerStub = stub(webauthn, "register").resolves(undefined);
      errorPopup = {
        style: {
          display: undefined,
        },
        textContent: undefined,
      };
      successPopup = {
        style: {
          display: undefined,
        },
        textContent: undefined,
      };
      registerButton = {
        addEventListener: fake(),
      };
      labelField = {
        value: undefined,
      };
      deleteForms = [];
      ui = {
        getSuccess: function () {
          return successPopup;
        },
        getError: function () {
          return errorPopup;
        },
        getRegisterButton: function () {
          return registerButton;
        },
        getLabelInput: function () {
          return labelField;
        },
        getDeleteForms: function () {
          return deleteForms;
        },
      };
      global.window = {
        location: {
          href: {},
        },
      };
      global.console = {
        error: stub(),
      };
    });

    afterEach(() => {
      registerStub.restore();
      delete global.window;
    });

    describe("when webauthn is not supported", () => {
      beforeEach(() => {
        delete global.window.PublicKeyCredential;
      });

      it("does not set up a click event listener", async () => {
        await setupRegistration({}, "/", ui);

        assert.notCalled(registerButton.addEventListener);
      });

      it("shows an error popup", async () => {
        await setupRegistration({}, "/", ui);

        expect(errorPopup).to.be.visible;
        expect(errorPopup.textContent).to.equal("WebAuthn is not supported");
        expect(successPopup).to.be.hidden;
      });
    });

    describe("when webauthn is supported", () => {
      beforeEach(() => {
        global.window.PublicKeyCredential = fake();
      });

      it("hides the popups", async () => {
        await setupRegistration({}, "/", ui);

        expect(successPopup).to.be.hidden;
        expect(errorPopup).to.be.hidden;
      });

      it("sets up a click event listener on the register button", async () => {
        await setupRegistration({}, "/some/path", ui);

        assert.calledOnceWithMatch(registerButton.addEventListener, "click", match.typeOf("function"));
      });

      describe(`when the query string contains "success"`, () => {
        beforeEach(() => {
          global.window.location.search = "?success&continue=true";
        });

        it("shows the success popup", async () => {
          await setupRegistration({}, "/", ui);

          expect(successPopup).to.be.visible;
          expect(errorPopup).to.be.hidden;
        });
      });

      describe("when the register button is clicked", () => {
        const headers = { "x-header": "value" };
        const contextPath = "/some/path";

        beforeEach(async () => {
          await setupRegistration(headers, contextPath, ui);
        });

        it("hides all the popups", async () => {
          successPopup.textContent = "dummy-content";
          successPopup.style.display = "block";
          errorPopup.textContent = "dummy-content";
          errorPopup.style.display = "block";

          await registerButton.addEventListener.firstCall.lastArg();

          expect(successPopup).to.be.hidden;
          expect(errorPopup).to.be.hidden;
        });

        it("calls register", async () => {
          labelField.value = "passkey name";

          await registerButton.addEventListener.firstCall.lastArg();

          assert.calledOnceWithExactly(registerStub, headers, contextPath, labelField.value);
        });

        it("navigates to success page", async () => {
          labelField.value = "passkey name";

          await registerButton.addEventListener.firstCall.lastArg();

          expect(global.window.location.href).to.equal(`${contextPath}/webauthn/register?success`);
        });

        it("handles errors", async () => {
          registerStub.rejects(new Error("The registration failed"));

          await registerButton.addEventListener.firstCall.lastArg();

          expect(errorPopup.textContent).to.equal("The registration failed");
          expect(errorPopup).to.be.visible;
          expect(successPopup).to.be.hidden;
          assert.calledOnceWithMatch(
            global.console.error,
            match.instanceOf(Error).and(match.has("message", "The registration failed")),
          );
        });
      });

      describe("delete", () => {
        beforeEach(() => {
          global.fetch = fake.resolves({ ok: true });
        });

        afterEach(() => {
          delete global.fetch;
        });

        it("no errors when no forms", async () => {
          await setupRegistration({}, "/some/path", ui);
        });

        it("sets up forms for fetch", async () => {
          const deleteFormOne = {
            addEventListener: fake(),
          };
          const deleteFormTwo = {
            addEventListener: fake(),
          };
          deleteForms = [deleteFormOne, deleteFormTwo];

          await setupRegistration({}, "", ui);

          assert.calledOnceWithMatch(deleteFormOne.addEventListener, "submit", match.typeOf("function"));
          assert.calledOnceWithMatch(deleteFormTwo.addEventListener, "submit", match.typeOf("function"));
        });

        describe("when the delete button is clicked", () => {
          it("calls POST to the form action", async () => {
            const contextPath = "/some/path";
            const deleteForm = {
              addEventListener: fake(),
              action: `${contextPath}/webauthn/1234`,
            };
            deleteForms = [deleteForm];
            const headers = {
              "X-CSRF-TOKEN": "token",
            };

            await setupRegistration(headers, contextPath, ui);

            const clickEvent = {
              preventDefault: fake(),
            };
            await deleteForm.addEventListener.firstCall.lastArg(clickEvent);
            assert.calledOnce(clickEvent.preventDefault);
            assert.calledOnceWithExactly(global.fetch, `/some/path/webauthn/1234`, {
              method: "DELETE",
              headers: {
                "Content-Type": "application/json",
                ...headers,
              },
            });
            expect(global.window.location.href).to.equal(`/some/path/webauthn/register?success`);
          });
        });

        it("handles errors", async () => {
          global.fetch = fake.rejects("Server threw an error");
          global.window.location.href = "/initial/location";
          const deleteForm = {
            addEventListener: fake(),
          };
          deleteForms = [deleteForm];

          await setupRegistration({}, "", ui);
          const clickEvent = { preventDefault: fake() };
          await deleteForm.addEventListener.firstCall.lastArg(clickEvent);

          expect(errorPopup).to.be.visible;
          expect(errorPopup.textContent).to.equal("Server threw an error");
          // URL does not change
          expect(global.window.location.href).to.equal("/initial/location");
        });
      });
    });
  });
});
