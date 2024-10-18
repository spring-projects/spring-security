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

package org.springframework.security.web.webauthn.api;

import java.util.List;

/**
 * <a href=
 * "https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientoutputs">AuthenticationExtensionsClientOutputs</a>
 * is a dictionary containing the
 * <a href="https://www.w3.org/TR/webauthn-3/#client-extension-output">client extension
 * output</a> values for zero or more
 * <a href="https://www.w3.org/TR/webauthn-3/#webauthn-extensions">WebAuthn
 * Extensions</a>.
 *
 * @author Rob Winch
 * @since 6.4
 * @see PublicKeyCredential#getClientExtensionResults()
 */
public interface AuthenticationExtensionsClientOutputs {

	/**
	 * Gets all of the {@link AuthenticationExtensionsClientOutput}.
	 * @return a non-null {@link List} of {@link AuthenticationExtensionsClientOutput}.
	 */
	List<AuthenticationExtensionsClientOutput<?>> getOutputs();

}
