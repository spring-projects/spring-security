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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.passwordless.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

public class OneTimeTokenAuthenticationConverter implements AuthenticationConverter {

	private final Log logger = LogFactory.getLog(getClass());

	private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/login/ott", "POST");

	@Override
	public Authentication convert(HttpServletRequest request) {
		if (!this.requestMatcher.matches(request)) {
			return null;
		}
		String token = request.getParameter("token");
		if (!StringUtils.hasText(token)) {
			this.logger.debug("No token found in request");
			return null;
		}
		return new OneTimeTokenAuthenticationToken(token);
	}

}
