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

const holder = {
  controller: new AbortController(),
};

/**
 * Returns a new AbortSignal to be used in the options for the registration and authentication ceremonies.
 * Aborts the existing AbortController if it exists, cancelling any existing ceremony.
 *
 * The authentication ceremony, when triggered with conditional mediation, shows a non-modal
 * interaction. If the user does not interact with the non-modal dialog, the existing ceremony MUST
 * be cancelled before initiating a new one, hence the need for a singleton AbortController.
 *
 * @returns {AbortSignal} a new, non-aborted AbortSignal
 */
function newSignal() {
  if (!!holder.controller) {
    holder.controller.abort("Initiating new WebAuthN ceremony, cancelling current ceremony");
  }
  holder.controller = new AbortController();
  return holder.controller.signal;
}

export default {
  newSignal,
};
