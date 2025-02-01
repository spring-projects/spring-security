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
import { expect } from "chai";
import { assert, fake, match, stub } from "sinon";
import http from "../lib/http.js";
import webauthn from "../lib/webauthn-core.js";
import base64url from "../lib/base64url.js";

describe("webauthn-core", () => {
  beforeEach(() => {
    global.window = {
      btoa: (str) => Buffer.from(str, "binary").toString("base64"),
      atob: (b64) => Buffer.from(b64, "base64").toString("binary"),
    };
  });

  afterEach(() => {
    delete global.window;
  });

  describe("isConditionalMediationAvailable", () => {
    afterEach(() => {
      delete global.window.PublicKeyCredential;
    });

    it("is available", async () => {
      global.window = {
        PublicKeyCredential: {
          isConditionalMediationAvailable: fake.resolves(true),
        },
      };

      const result = await webauthn.isConditionalMediationAvailable();

      expect(result).to.be.true;
    });

    describe("is not available", async () => {
      it("PublicKeyCredential does not exist", async () => {
        global.window = {};
        const result = await webauthn.isConditionalMediationAvailable();
        expect(result).to.be.false;
      });
      it("PublicKeyCredential.isConditionalMediationAvailable undefined", async () => {
        global.window = {
          PublicKeyCredential: {},
        };
        const result = await webauthn.isConditionalMediationAvailable();
        expect(result).to.be.false;
      });
      it("PublicKeyCredential.isConditionalMediationAvailable false", async () => {
        global.window = {
          PublicKeyCredential: {
            isConditionalMediationAvailable: fake.resolves(false),
          },
        };
        const result = await webauthn.isConditionalMediationAvailable();
        expect(result).to.be.false;
      });
    });
  });

  describe("authenticate", () => {
    let httpPostStub;
    const contextPath = "/some/path";

    const credentialsGetOptions = {
      challenge: "nRbOrtNKTfJ1JaxfUDKs8j3B-JFqyGQw8DO4u6eV3JA",
      timeout: 300000,
      rpId: "localhost",
      allowCredentials: [
        {
          id: "nOsjw8eaaqSwVdTBBYE1FqfGdHs",
          type: "public-key",
          transports: [],
        },
      ],
      userVerification: "preferred",
      extensions: {},
    };

    // This is kind of a self-fulfilling prophecy type of test: we produce array buffers by calling
    // base64url.decode ; they will then be re-encoded to the same string in the production code.
    // The ArrayBuffer API is not super friendly.
    beforeEach(() => {
      httpPostStub = stub(http, "post");
      httpPostStub.withArgs(contextPath + "/webauthn/authenticate/options", match.any).resolves({
        ok: true,
        status: 200,
        json: fake.resolves(credentialsGetOptions),
      });
      httpPostStub.withArgs(`${contextPath}/login/webauthn`, match.any, match.any).resolves({
        ok: true,
        status: 200,
        json: fake.resolves({
          authenticated: true,
          redirectUrl: "/success",
        }),
      });

      const validAuthenticatorResponse = {
        id: "UgghgP5QKozwsSUK1twCj8mpgZs",
        rawId: base64url.decode("UgghgP5QKozwsSUK1twCj8mpgZs"),
        response: {
          authenticatorData: base64url.decode("y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNgdAAAAAA"),
          clientDataJSON: base64url.decode(
            "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUTdlR0NkNUw2cG9fa01meWNIQnBWRlR5dmd3RklCV0QxZWg5OUktRFhnWSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyJ9",
          ),
          signature: base64url.decode(
            "MEUCIGT9PAWfU3lMicOXFMpHGcl033dY-sNSJvehlXvvoivyAiEA_D_yOsChERlXX2rFcK6Qx5BaAbx5qdU2hgYDVN6W770",
          ),
          userHandle: base64url.decode("tyRDnKxdj7uWOT5jrchXu54lo6nf3bWOUvMQnGOXk7g"),
        },
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: "platform",
        type: "public-key",
      };
      global.navigator = {
        credentials: {
          get: fake.resolves(validAuthenticatorResponse),
        },
      };
    });

    afterEach(() => {
      http.post.restore();
      delete global.navigator;
    });

    it("succeeds", async () => {
      const redirectUrl = await webauthn.authenticate({ "x-custom": "some-value" }, contextPath, false);

      expect(redirectUrl).to.equal("/success");
      assert.calledWith(
        httpPostStub.lastCall,
        `${contextPath}/login/webauthn`,
        { "x-custom": "some-value" },
        {
          id: "UgghgP5QKozwsSUK1twCj8mpgZs",
          rawId: "UgghgP5QKozwsSUK1twCj8mpgZs",
          credType: "public-key",
          response: {
            authenticatorData: "y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNgdAAAAAA",
            clientDataJSON:
              "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUTdlR0NkNUw2cG9fa01meWNIQnBWRlR5dmd3RklCV0QxZWg5OUktRFhnWSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyJ9",
            signature:
              "MEUCIGT9PAWfU3lMicOXFMpHGcl033dY-sNSJvehlXvvoivyAiEA_D_yOsChERlXX2rFcK6Qx5BaAbx5qdU2hgYDVN6W770",
            userHandle: "tyRDnKxdj7uWOT5jrchXu54lo6nf3bWOUvMQnGOXk7g",
          },
          clientExtensionResults: {},
          authenticatorAttachment: "platform",
        },
      );
    });

    it("calls the authenticator with the correct options", async () => {
      await webauthn.authenticate({}, contextPath, false);

      assert.calledOnceWithMatch(global.navigator.credentials.get, {
        publicKey: {
          challenge: base64url.decode("nRbOrtNKTfJ1JaxfUDKs8j3B-JFqyGQw8DO4u6eV3JA"),
          timeout: 300000,
          rpId: "localhost",
          allowCredentials: [
            {
              id: base64url.decode("nOsjw8eaaqSwVdTBBYE1FqfGdHs"),
              type: "public-key",
              transports: [],
            },
          ],
          userVerification: "preferred",
          extensions: {},
        },
        signal: match.any,
      });
    });

    describe("authentication failures", () => {
      it("when authentication options call", async () => {
        httpPostStub
          .withArgs(`${contextPath}/webauthn/authenticate/options`, match.any)
          .rejects(new Error("Connection refused"));

        try {
          await webauthn.authenticate({}, contextPath, false);
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            "Authentication failed. Could not fetch authentication options: Connection refused",
          );
          return;
        }
        expect.fail("authenticate should throw");
      });

      it("when authentication options call returns does not return HTTP 200 OK", async () => {
        httpPostStub.withArgs(`${contextPath}/webauthn/authenticate/options`, match.any).resolves({
          ok: false,
          status: 400,
        });

        try {
          await webauthn.authenticate({}, contextPath, false);
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal("Authentication failed. Could not fetch authentication options: HTTP 400");
          return;
        }
        expect.fail("authenticate should throw");
      });

      it("when authentication options are not valid json", async () => {
        httpPostStub.withArgs(`${contextPath}/webauthn/authenticate/options`, match.any).resolves({
          ok: true,
          status: 200,
          json: fake.rejects(new Error("Not valid JSON")),
        });

        try {
          await webauthn.authenticate({}, contextPath, false);
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal("Authentication failed. Could not fetch authentication options: Not valid JSON");
          return;
        }
        expect.fail("authenticate should throw");
      });

      it("when navigator.credentials.get fails", async () => {
        global.navigator.credentials.get = fake.rejects(new Error("Operation was aborted"));
        try {
          await webauthn.authenticate({}, contextPath, false);
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            "Authentication failed. Call to navigator.credentials.get failed: Operation was aborted",
          );
          return;
        }
        expect.fail("authenticate should throw");
      });

      it("when authentication call fails", async () => {
        httpPostStub
          .withArgs(`${contextPath}/login/webauthn`, match.any, match.any)
          .rejects(new Error("Connection refused"));
        try {
          await webauthn.authenticate({}, contextPath, false);
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            "Authentication failed. Could not process the authentication request: Connection refused",
          );
          return;
        }
        expect.fail("authenticate should throw");
      });

      it("when authentication call does not return HTTP 200 OK", async () => {
        httpPostStub.withArgs(`${contextPath}/login/webauthn`, match.any, match.any).resolves({
          ok: false,
          status: 400,
        });
        try {
          await webauthn.authenticate({}, contextPath, false);
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal("Authentication failed. Could not process the authentication request: HTTP 400");
          return;
        }
        expect.fail("authenticate should throw");
      });

      it("when authentication call does not return JSON", async () => {
        httpPostStub.withArgs(`${contextPath}/login/webauthn`, match.any, match.any).resolves({
          ok: true,
          status: 200,
          json: fake.rejects(new Error("Not valid JSON")),
        });
        try {
          await webauthn.authenticate({}, contextPath, false);
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            "Authentication failed. Could not process the authentication request: Not valid JSON",
          );
          return;
        }
        expect.fail("authenticate should throw");
      });

      it("when authentication call returns null", async () => {
        httpPostStub.withArgs(`${contextPath}/login/webauthn`, match.any, match.any).resolves({
          ok: true,
          status: 200,
          json: fake.resolves(null),
        });
        try {
          await webauthn.authenticate({}, contextPath, false);
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            'Authentication failed. Expected {"authenticated": true, "redirectUrl": "..."}, server responded with: null',
          );
          return;
        }
        expect.fail("authenticate should throw");
      });

      it('when authentication call returns {"authenticated":false}', async () => {
        httpPostStub.withArgs(`${contextPath}/login/webauthn`, match.any, match.any).resolves({
          ok: true,
          status: 200,
          json: fake.resolves({
            authenticated: false,
          }),
        });
        try {
          await webauthn.authenticate({}, contextPath, false);
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            'Authentication failed. Expected {"authenticated": true, "redirectUrl": "..."}, server responded with: {"authenticated":false}',
          );
          return;
        }
        expect.fail("authenticate should throw");
      });

      it("when authentication call returns no redirectUrl", async () => {
        httpPostStub.withArgs(`${contextPath}/login/webauthn`, match.any, match.any).resolves({
          ok: true,
          status: 200,
          json: fake.resolves({
            authenticated: true,
          }),
        });
        try {
          await webauthn.authenticate({}, contextPath, false);
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            'Authentication failed. Expected {"authenticated": true, "redirectUrl": "..."}, server responded with: {"authenticated":true}',
          );
          return;
        }
        expect.fail("authenticate should throw");
      });
    });
  });

  describe("register", () => {
    let httpPostStub;
    const contextPath = "/some/path";

    beforeEach(() => {
      const credentialsCreateOptions = {
        rp: {
          name: "Spring Security Relying Party",
          id: "example.localhost",
        },
        user: {
          name: "user",
          id: "eatPy60xmXG_58JrIiIBa5wq8Y76c7MD6mnY5vW8yP8",
          displayName: "user",
        },
        challenge: "s0hBOfkSaVLXdsbyD8jii6t2IjUd-eiTP1Cmeuo1qUo",
        pubKeyCredParams: [
          {
            type: "public-key",
            alg: -8,
          },
          {
            type: "public-key",
            alg: -7,
          },
          {
            type: "public-key",
            alg: -257,
          },
        ],
        timeout: 300000,
        excludeCredentials: [
          {
            id: "nOsjw8eaaqSwVdTBBYE1FqfGdHs",
            type: "public-key",
            transports: [],
          },
        ],
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "preferred",
        },
        attestation: "direct",
        extensions: { credProps: true },
      };
      const validAuthenticatorResponse = {
        authenticatorAttachment: "platform",
        id: "9wAuex_025BgEQrs7fOypo5SGBA",
        rawId: base64url.decode("9wAuex_025BgEQrs7fOypo5SGBA"),
        response: {
          attestationObject: base64url.decode(
            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYy9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAAPv8MAcVTk7MjAtuAgVX170AFPcALnsf9NuQYBEK7O3zsqaOUhgQpQECAyYgASFYIMB9pM2BeSeEG83fAKFVSLKIfvDBBVoyGgMoiGxE-6WgIlggazAojM5sduQy2M7rz1do55nVaNLGXh8k4xBHz-Oy91E",
          ),
          getAuthenticatorData: () =>
            base64url.decode(
              "y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAAPv8MAcVTk7MjAtuAgVX170AFPcALnsf9NuQYBEK7O3zsqaOUhgQpQECAyYgASFYIMB9pM2BeSeEG83fAKFVSLKIfvDBBVoyGgMoiGxE-6WgIlggazAojM5sduQy2M7rz1do55nVaNLGXh8k4xBHz-Oy91E",
            ),
          clientDataJSON: base64url.decode(
            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUVdwd3lUcXJpYVlqbVdnOWFvZ0FxUlRKNVFYMFBGV2JWR2xNeGNsVjZhcyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyJ9",
          ),
          getPublicKey: () =>
            base64url.decode(
              "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwH2kzYF5J4Qbzd8AoVVIsoh-8MEFWjIaAyiIbET7paBrMCiMzmx25DLYzuvPV2jnmdVo0sZeHyTjEEfP47L3UQ",
            ),
          getPublicKeyAlgorithm: () => -7,
          getTransports: () => ["internal"],
        },
        type: "public-key",
        getClientExtensionResults: () => ({}),
      };
      global.navigator = {
        credentials: {
          create: fake.resolves(validAuthenticatorResponse),
        },
      };
      httpPostStub = stub(http, "post");
      httpPostStub.withArgs(contextPath + "/webauthn/register/options", match.any).resolves({
        ok: true,
        status: 200,
        json: fake.resolves(credentialsCreateOptions),
      });
      httpPostStub.withArgs(`${contextPath}/webauthn/register`, match.any, match.any).resolves({
        ok: true,
        json: fake.resolves({
          success: true,
        }),
      });
    });

    afterEach(() => {
      httpPostStub.restore();
      delete global.navigator;
    });

    it("succeeds", async () => {
      const contextPath = "/some/path";
      const headers = { _csrf: "csrf-value" };

      await webauthn.register(headers, contextPath, "my passkey");
      assert.calledWithExactly(
        httpPostStub.lastCall,
        `${contextPath}/webauthn/register`,
        headers,
        match({
          publicKey: {
            credential: {
              id: "9wAuex_025BgEQrs7fOypo5SGBA",
              rawId: "9wAuex_025BgEQrs7fOypo5SGBA",
              response: {
                attestationObject:
                  "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYy9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAAPv8MAcVTk7MjAtuAgVX170AFPcALnsf9NuQYBEK7O3zsqaOUhgQpQECAyYgASFYIMB9pM2BeSeEG83fAKFVSLKIfvDBBVoyGgMoiGxE-6WgIlggazAojM5sduQy2M7rz1do55nVaNLGXh8k4xBHz-Oy91E",
                clientDataJSON:
                  "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUVdwd3lUcXJpYVlqbVdnOWFvZ0FxUlRKNVFYMFBGV2JWR2xNeGNsVjZhcyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyJ9",
                transports: ["internal"],
              },
              type: "public-key",
              clientExtensionResults: {},
              authenticatorAttachment: "platform",
            },
            label: "my passkey",
          },
        }),
      );
    });

    it("calls the authenticator with the correct options", async () => {
      await webauthn.register({}, contextPath, "my passkey");

      assert.calledOnceWithExactly(
        global.navigator.credentials.create,
        match({
          publicKey: {
            rp: {
              name: "Spring Security Relying Party",
              id: "example.localhost",
            },
            user: {
              name: "user",
              id: base64url.decode("eatPy60xmXG_58JrIiIBa5wq8Y76c7MD6mnY5vW8yP8"),
              displayName: "user",
            },
            challenge: base64url.decode("s0hBOfkSaVLXdsbyD8jii6t2IjUd-eiTP1Cmeuo1qUo"),
            pubKeyCredParams: [
              {
                type: "public-key",
                alg: -8,
              },
              {
                type: "public-key",
                alg: -7,
              },
              {
                type: "public-key",
                alg: -257,
              },
            ],
            timeout: 300000,
            excludeCredentials: [
              {
                id: base64url.decode("nOsjw8eaaqSwVdTBBYE1FqfGdHs"),
                type: "public-key",
                transports: [],
              },
            ],
            authenticatorSelection: {
              residentKey: "required",
              userVerification: "preferred",
            },
            attestation: "direct",
            extensions: { credProps: true },
          },
          signal: match.any,
        }),
      );
    });

    describe("registration failures", () => {
      it("when label is missing", async () => {
        try {
          await webauthn.register({}, "/", "");
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal("Error: Passkey Label is required");
          return;
        }
        expect.fail("register should throw");
      });

      it("when cannot get the registration options", async () => {
        httpPostStub.withArgs(match.any, match.any).rejects(new Error("Server threw an error"));
        try {
          await webauthn.register({}, "/", "my passkey");
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            "Registration failed. Could not fetch registration options: Server threw an error",
          );
          return;
        }
        expect.fail("register should throw");
      });

      it("when registration options call does not return HTTP 200 OK", async () => {
        httpPostStub.withArgs(match.any, match.any).resolves({
          ok: false,
          status: 400,
        });
        try {
          await webauthn.register({}, "/", "my passkey");
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            "Registration failed. Could not fetch registration options: Server responded with HTTP 400",
          );
          return;
        }
        expect.fail("register should throw");
      });

      it("when registration options are not valid JSON", async () => {
        httpPostStub.withArgs(match.any, match.any).resolves({
          ok: true,
          status: 200,
          json: fake.rejects(new Error("Not a JSON response")),
        });
        try {
          await webauthn.register({}, "/", "my passkey");
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            "Registration failed. Could not fetch registration options: Not a JSON response",
          );
          return;
        }
        expect.fail("register should throw");
      });

      it("when navigator.credentials.create fails", async () => {
        global.navigator = {
          credentials: {
            create: fake.rejects(new Error("authenticator threw an error")),
          },
        };
        try {
          await webauthn.register({}, contextPath, "my passkey");
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            "Registration failed. Call to navigator.credentials.create failed: authenticator threw an error",
          );
          expect(err.cause).to.deep.equal(new Error("authenticator threw an error"));
          return;
        }
        expect.fail("register should throw");
      });

      it("when registration call fails", async () => {
        httpPostStub
          .withArgs(`${contextPath}/webauthn/register`, match.any, match.any)
          .rejects(new Error("Connection refused"));
        try {
          await webauthn.register({}, contextPath, "my passkey");
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            "Registration failed. Could not process the registration request: Connection refused",
          );
          expect(err.cause).to.deep.equal(new Error("Connection refused"));
          return;
        }
        expect.fail("register should throw");
      });

      it("when registration call does not return HTTP 200 OK", async () => {
        httpPostStub.withArgs(`${contextPath}/webauthn/register`, match.any, match.any).resolves({
          ok: false,
          status: 400,
        });
        try {
          await webauthn.register({}, contextPath, "my passkey");
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal("Registration failed. Could not process the registration request: HTTP 400");
          return;
        }
        expect.fail("register should throw");
      });

      it("when registration call does not return JSON", async () => {
        httpPostStub.withArgs(`${contextPath}/webauthn/register`, match.any, match.any).resolves({
          ok: true,
          status: 200,
          json: fake.rejects(new Error("Not valid JSON")),
        });
        try {
          await webauthn.register({}, contextPath, "my passkey");
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal(
            "Registration failed. Could not process the registration request: Not valid JSON",
          );
          expect(err.cause).to.deep.equal(new Error("Not valid JSON"));
          return;
        }
        expect.fail("register should throw");
      });

      it("when registration call returns null", async () => {
        httpPostStub.withArgs(`${contextPath}/webauthn/register`, match.any, match.any).resolves({
          ok: true,
          status: 200,
          json: fake.resolves(null),
        });
        try {
          await webauthn.register({}, contextPath, "my passkey");
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal("Registration failed. Server responded with: null");
          return;
        }
        expect.fail("register should throw");
      });

      it('when registration call returns {"success":false}', async () => {
        httpPostStub.withArgs(`${contextPath}/webauthn/register`, match.any, match.any).resolves({
          ok: true,
          status: 200,
          json: fake.resolves({ success: false }),
        });
        try {
          await webauthn.register({}, contextPath, "my passkey");
        } catch (err) {
          expect(err).to.be.an("error");
          expect(err.message).to.equal('Registration failed. Server responded with: {"success":false}');
          return;
        }
        expect.fail("register should throw");
      });
    });
  });
});
