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

import webauthn from "./webauthn-core.js";

function setVisibility(element, value) {
  if (!element) {
    return;
  }
  element.style.display = value ? "block" : "none";
}

function setError(ui, msg) {
  resetPopups(ui);
  const error = ui.getError();
  if (!error) {
    return;
  }
  error.textContent = msg;
  setVisibility(error, true);
}

function setSuccess(ui) {
  resetPopups(ui);
  const success = ui.getSuccess();
  if (!success) {
    return;
  }
  setVisibility(success, true);
}

function resetPopups(ui) {
  const success = ui.getSuccess();
  const error = ui.getError();
  setVisibility(success, false);
  setVisibility(error, false);
}

async function submitDeleteForm(contextPath, form, headers) {
  const options = {
    method: "DELETE",
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  };
  await fetch(form.action, options);
}

/**
 *
 * @param headers headers added to the credentials creation POST request, typically CSRF
 * @param contextPath the contextPath from which the app is served
 * @param ui contains getRegisterButton(), getSuccess(), getError(), getLabelInput(), getDeleteForms()
 * @returns {Promise<void>}
 */
export async function setupRegistration(headers, contextPath, ui) {
  resetPopups(ui);

  if (!window.PublicKeyCredential) {
    setError(ui, "WebAuthn is not supported");
    return;
  }

  const queryString = new URLSearchParams(window.location.search);
  if (queryString.has("success")) {
    setSuccess(ui);
  }

  ui.getRegisterButton().addEventListener("click", async () => {
    resetPopups(ui);
    const label = ui.getLabelInput().value;
    try {
      await webauthn.register(headers, contextPath, label);
      window.location.href = `${contextPath}/webauthn/register?success`;
    } catch (err) {
      setError(ui, err.message);
      console.error(err);
    }
  });

  ui.getDeleteForms().forEach((form) =>
    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      try {
        await submitDeleteForm(contextPath, form, headers);
        window.location.href = `${contextPath}/webauthn/register?success`;
      } catch (err) {
        setError(ui, err.message);
      }
    }),
  );
}
