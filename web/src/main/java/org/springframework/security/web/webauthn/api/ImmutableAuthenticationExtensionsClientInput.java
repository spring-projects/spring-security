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

/**
 * An immutable {@link AuthenticationExtensionsClientInput}.
 *
 * @param <T> the input type
 * @author Rob Winch
 * @since 6.4
 * @see AuthenticationExtensionsClientInputs
 */
public class ImmutableAuthenticationExtensionsClientInput<T> implements AuthenticationExtensionsClientInput<T> {

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension
	 */
	public static final AuthenticationExtensionsClientInput<Boolean> credProps = new ImmutableAuthenticationExtensionsClientInput<>(
			"credProps", true);

	private final String extensionId;

	private final T input;

	/**
	 * Creates a new instance
	 * @param extensionId the extension id.
	 * @param input the input.
	 */
	public ImmutableAuthenticationExtensionsClientInput(String extensionId, T input) {
		this.extensionId = extensionId;
		this.input = input;
	}

	@Override
	public String getExtensionId() {
		return this.extensionId;
	}

	@Override
	public T getInput() {
		return this.input;
	}

}
