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

package org.springframework.security.web.webauthn.registration;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;

/**
 * Saves {@link PublicKeyCredentialCreationOptions} between a request to generate an
 * assertion and the validation of the assertion.
 *
 * @author Rob Winch
 * @since 6.4
 */
public interface PublicKeyCredentialCreationOptionsRepository {

	/**
	 * Saves the provided {@link PublicKeyCredentialCreationOptions} or clears an existing
	 * {@link PublicKeyCredentialCreationOptions} if {@code options} is null.
	 * @param request the {@link HttpServletRequest}
	 * @param response the {@link HttpServletResponse}
	 * @param options the {@link PublicKeyCredentialCreationOptions} to save or null if an
	 * existing {@link PublicKeyCredentialCreationOptions} should be removed.
	 */
	void save(HttpServletRequest request, HttpServletResponse response, PublicKeyCredentialCreationOptions options);

	/**
	 * Gets a saved {@link PublicKeyCredentialCreationOptions} if it exists, otherwise
	 * null.
	 * @param request the {@link HttpServletRequest}
	 * @return the {@link PublicKeyCredentialCreationOptions} that was saved, otherwise
	 * null.
	 */
	PublicKeyCredentialCreationOptions load(HttpServletRequest request);

}
