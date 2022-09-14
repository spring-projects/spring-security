/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.saml2.core;

/**
 * Standard parameter names defined in the SAML 2.0 Specification and used by the
 * Authentication Request, Assertion Consumer Response, Logout Request, and Logout
 * Response endpoints.
 *
 * @author Josh Cummings
 * @since 5.6
 * @see <a target="_blank" href=
 * "https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf">SAML 2.0
 * Bindings</a>
 */
public final class Saml2ParameterNames {

	/**
	 * {@code SAMLRequest} - used to request authentication or request logout
	 */
	public static final String SAML_REQUEST = "SAMLRequest";

	/**
	 * {@code SAMLResponse} - used to respond to an authentication or logout request
	 */
	public static final String SAML_RESPONSE = "SAMLResponse";

	/**
	 * {@code RelayState} - used to communicate shared state between the relying and
	 * asserting party
	 * @see <a target="_blank" href=
	 * "https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf#page=8">3.1.1
	 * Use of RelayState</a>
	 */
	public static final String RELAY_STATE = "RelayState";

	/**
	 * {@code SigAlg} - used to communicate which signature algorithm to use to verify
	 * signature
	 */
	public static final String SIG_ALG = "SigAlg";

	/**
	 * {@code Signature} - used to supply cryptographic signature on any SAML 2.0 payload
	 */
	public static final String SIGNATURE = "Signature";

	private Saml2ParameterNames() {
	}

}
