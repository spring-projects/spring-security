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

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.endpoint.AuthorizationCodeAuthorizationResponseAttributes;
import org.springframework.security.oauth2.core.endpoint.OAuth2Parameter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

/**
 * An implementation of a {@link Converter} that converts an <i>OAuth 2.0 Authorization Code Grant Response</i>
 * (in the form of a {@link HttpServletRequest}) to a {@link AuthorizationCodeAuthorizationResponseAttributes}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationCodeAuthorizationResponseAttributes
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Code Grant Response</a>
 */
public final class AuthorizationCodeAuthorizationResponseAttributesConverter implements Converter<HttpServletRequest, AuthorizationCodeAuthorizationResponseAttributes> {

	@Override
	public AuthorizationCodeAuthorizationResponseAttributes convert(HttpServletRequest request) {
		AuthorizationCodeAuthorizationResponseAttributes response;

		String code = request.getParameter(OAuth2Parameter.CODE);
		Assert.hasText(code, OAuth2Parameter.CODE + " attribute is required");

		String state = request.getParameter(OAuth2Parameter.STATE);

		response = new AuthorizationCodeAuthorizationResponseAttributes(code, state);

		return response;
	}
}
