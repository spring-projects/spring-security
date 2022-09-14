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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

/**
 * Utility methods for working with {@link Saml2MessageBinding}
 *
 * For internal use only.
 *
 * @since 5.8
 */
final class Saml2MessageBindingUtils {

	private Saml2MessageBindingUtils() {
	}

	static Saml2MessageBinding resolveBinding(HttpServletRequest request) {
		if (isHttpPostBinding(request)) {
			return Saml2MessageBinding.POST;
		}
		else if (isHttpRedirectBinding(request)) {
			return Saml2MessageBinding.REDIRECT;
		}
		throw new Saml2Exception("Unable to determine message binding from request.");
	}

	private static boolean isSamlRequestResponse(HttpServletRequest request) {
		return (request.getParameter(Saml2ParameterNames.SAML_REQUEST) != null
				|| request.getParameter(Saml2ParameterNames.SAML_RESPONSE) != null);
	}

	static boolean isHttpRedirectBinding(HttpServletRequest request) {
		return request != null && "GET".equalsIgnoreCase(request.getMethod()) && isSamlRequestResponse(request);
	}

	static boolean isHttpPostBinding(HttpServletRequest request) {
		return request != null && "POST".equalsIgnoreCase(request.getMethod()) && isSamlRequestResponse(request);
	}

}
