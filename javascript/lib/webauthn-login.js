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

async function authenticateOrError(headers, contextPath, useConditionalMediation) {
  try {
    const redirectUrl = await webauthn.authenticate(headers, contextPath, useConditionalMediation);
    window.location.href = redirectUrl;
  } catch (err) {
    console.error(err);
    window.location.href = `${contextPath}/login?error`;
  }
}

async function conditionalMediation(headers, contextPath) {
  const available = await webauthn.isConditionalMediationAvailable();
  if (available) {
    await authenticateOrError(headers, contextPath, true);
  }
  return available;
}

export async function setupLogin(headers, contextPath, signinButton) {
  signinButton.addEventListener("click", async () => {
    await authenticateOrError(headers, contextPath, false);
  });

  // FIXME: conditional mediation triggers browser crashes
  // See: https://github.com/rwinch/spring-security-webauthn/issues/73
  // await conditionalMediation(headers, contextPath);
}
