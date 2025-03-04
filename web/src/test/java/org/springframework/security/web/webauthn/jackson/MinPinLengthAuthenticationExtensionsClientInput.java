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

package org.springframework.security.web.webauthn.jackson;

import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInput;

/**
 * Implements <a href=
 * "https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-minpinlength-extension">
 * Minimum PIN Length Extension (minPinLength)</a>.
 *
 * @author Justin Cranford
 * @since 6.5
 */
record MinPinLengthAuthenticationExtensionsClientInput(Boolean getInput) implements AuthenticationExtensionsClientInput<Boolean> {
	@Override
	public String getExtensionId() {
		return "minPinLength";
	}
}
