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

package org.springframework.security.web.csrf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.util.Assert;

/**
 * {@link CsrfAuthenticationStrategy} is in charge of removing the {@link CsrfToken} upon
 * authenticating. A new {@link CsrfToken} will then be generated by the framework upon
 * the next request.
 *
 * @author Rob Winch
 * @author Steve Riesenberg
 * @since 3.2
 */
public final class CsrfAuthenticationStrategy implements SessionAuthenticationStrategy {

	private final Log logger = LogFactory.getLog(getClass());

	private final CsrfTokenRepository tokenRepository;

	private CsrfTokenRequestHandler requestHandler = new XorCsrfTokenRequestAttributeHandler();

	/**
	 * Creates a new instance
	 * @param tokenRepository the {@link CsrfTokenRepository} to use
	 */
	public CsrfAuthenticationStrategy(CsrfTokenRepository tokenRepository) {
		Assert.notNull(tokenRepository, "tokenRepository cannot be null");
		this.tokenRepository = tokenRepository;
	}

	/**
	 * Specify a {@link CsrfTokenRequestHandler} to use for making the {@code CsrfToken}
	 * available as a request attribute.
	 * @param requestHandler the {@link CsrfTokenRequestHandler} to use
	 */
	public void setRequestHandler(CsrfTokenRequestHandler requestHandler) {
		Assert.notNull(requestHandler, "requestHandler cannot be null");
		this.requestHandler = requestHandler;
	}

	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) throws SessionAuthenticationException {
		boolean containsToken = this.tokenRepository.loadToken(request) != null;
		if (containsToken) {
			this.tokenRepository.saveToken(null, request, response);
			DeferredCsrfToken deferredCsrfToken = this.tokenRepository.loadDeferredToken(request, response);
			this.requestHandler.handle(request, response, deferredCsrfToken);
			this.logger.debug("Replaced CSRF Token");
		}
	}

}
