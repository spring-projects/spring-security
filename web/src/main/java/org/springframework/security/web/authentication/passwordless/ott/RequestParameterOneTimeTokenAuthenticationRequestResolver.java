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

package org.springframework.security.web.authentication.passwordless.ott;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.passwordless.ott.OneTimeTokenAuthenticationRequest;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class RequestParameterOneTimeTokenAuthenticationRequestResolver
		implements OneTimeTokenAuthenticationRequestResolver {

	private String usernameParameter = "username";

	public RequestParameterOneTimeTokenAuthenticationRequestResolver() {
	}

	public RequestParameterOneTimeTokenAuthenticationRequestResolver(String usernameParameter) {
		Assert.hasText(usernameParameter, "usernameParameter cannot be null or empty");
		this.usernameParameter = usernameParameter;
	}

	@Override
	public OneTimeTokenAuthenticationRequest resolve(HttpServletRequest request) {
		String username = request.getParameter(this.usernameParameter);
		if (!StringUtils.hasText(username)) {
			return null;
		}
		return new OneTimeTokenAuthenticationRequest(username);
	}

}
