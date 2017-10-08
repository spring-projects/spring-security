/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web.converter;

import org.springframework.security.oauth2.core.endpoint.AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2Parameter;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.function.Function;

/**
 * A <code>Function</code> that converts an <i>OAuth 2.0 Authorization Code Grant Response</i>
 * (in the form of a {@link HttpServletRequest}) to a {@link AuthorizationResponse}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationResponse
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Code Grant Response</a>
 */
public final class AuthorizationResponseConverter implements Function<HttpServletRequest, AuthorizationResponse> {

	@Override
	public AuthorizationResponse apply(HttpServletRequest request) {
		String code = request.getParameter(OAuth2Parameter.CODE);
		String errorCode = request.getParameter(OAuth2Parameter.ERROR);
		String state = request.getParameter(OAuth2Parameter.STATE);
		String redirectUri = request.getRequestURL().toString();

		if (StringUtils.hasText(code)) {
			return AuthorizationResponse.success(code)
				.redirectUri(redirectUri)
				.state(state)
				.build();
		} else if (StringUtils.hasText(errorCode)) {
			String description = request.getParameter(OAuth2Parameter.ERROR_DESCRIPTION);
			String uri = request.getParameter(OAuth2Parameter.ERROR_URI);
			return AuthorizationResponse.error(errorCode)
				.redirectUri(redirectUri)
				.errorDescription(description)
				.errorUri(uri)
				.state(state)
				.build();
		}

		return null;
	}
}
