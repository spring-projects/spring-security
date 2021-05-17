/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.provider.service.registration;

/**
 * The type of bindings that messages are exchanged using Supported bindings are
 * {@code urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST} and
 * {@code urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect}. In addition there is
 * support for {@code urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect} with an XML
 * signature in the message rather than query parameters.
 * @since 5.3
 */
public enum Saml2MessageBinding {

	POST("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"), REDIRECT(
			"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

	private final String urn;

	Saml2MessageBinding(String s) {
		this.urn = s;
	}

	/**
	 * Returns the URN value from the SAML 2 specification for this binding.
	 * @return URN value representing this binding
	 */
	public String getUrn() {
		return this.urn;
	}

	/**
	 * Attempt to resolve the provided algorithm name to a {@code Saml2MessageBinding}.
	 * @param name the algorithm name
	 * @return the resolved {@code Saml2MessageBinding}, or {@code null} if not found
	 * @since 5.5
	 */
	public static Saml2MessageBinding from(String name) {
		for (Saml2MessageBinding value : values()) {
			if (value.getUrn().equals(name)) {
				return value;
			}
		}
		return null;
	}

}
