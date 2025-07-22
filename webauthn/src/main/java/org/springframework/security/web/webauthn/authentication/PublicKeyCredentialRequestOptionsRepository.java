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

package org.springframework.security.web.webauthn.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;

/**
 * Saves {@link PublicKeyCredentialRequestOptions} between a request to generate an
 * assertion and the validation of the assertion.
 *
 * @author Rob Winch
 * @since 6.4
 */
public interface PublicKeyCredentialRequestOptionsRepository {

	/**
	 * Saves the provided {@link PublicKeyCredentialRequestOptions} or clears an existing
	 * {@link PublicKeyCredentialRequestOptions} if {@code options} is null.
	 * @param request the {@link HttpServletRequest}
	 * @param response the {@link HttpServletResponse}
	 * @param options the {@link PublicKeyCredentialRequestOptions} to save or null if an
	 * existing {@link PublicKeyCredentialRequestOptions} should be removed.
	 */
	void save(HttpServletRequest request, HttpServletResponse response, PublicKeyCredentialRequestOptions options);

	/**
	 * Gets a saved {@link PublicKeyCredentialRequestOptions} if it exists, otherwise
	 * null.
	 * @param request the {@link HttpServletRequest}
	 * @return the {@link PublicKeyCredentialRequestOptions} that was saved, otherwise
	 * null.
	 */
	PublicKeyCredentialRequestOptions load(HttpServletRequest request);

}
