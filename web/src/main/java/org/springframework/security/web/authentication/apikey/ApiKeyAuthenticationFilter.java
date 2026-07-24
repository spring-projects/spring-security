/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.authentication.apikey;

import java.io.IOException;
import java.util.Objects;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * @author Alexey Razinkov
 */
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

	private final AuthenticationManager authnManager;

	private final AuthenticationConverter authnConverter;

	private final SecurityContextHolderStrategy securityContextHolderStrategy;

	private final SecurityContextRepository securityContextRepository;

	@Nullable private final AuthenticationSuccessHandler successHandler;

	@Nullable private final AuthenticationFailureHandler failureHandler;

	public ApiKeyAuthenticationFilter(AuthenticationManager authnManager, AuthenticationConverter authnConverter,
			SecurityContextHolderStrategy securityContextHolderStrategy,
			SecurityContextRepository securityContextRepository, @Nullable AuthenticationSuccessHandler successHandler,
			@Nullable AuthenticationFailureHandler failureHandler) {
		this.authnManager = Objects.requireNonNull(authnManager);
		this.securityContextHolderStrategy = Objects.requireNonNull(securityContextHolderStrategy);
		this.authnConverter = Objects.requireNonNull(authnConverter);
		this.securityContextRepository = Objects.requireNonNull(securityContextRepository);
		this.successHandler = successHandler;
		this.failureHandler = failureHandler;
	}

	@Override
	protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
			final FilterChain filterChain) throws ServletException, IOException {
		try {
			final Authentication authRequest = this.authnConverter.convert(request);
			if (authRequest == null) {
				this.logger.trace("Did not process authentication request since failed to find API key token");
				filterChain.doFilter(request, response);
				return;
			}
			final String apiKeyId = authRequest.getName();
			this.logger.trace(LogMessage.format("Found API key '%s'", apiKeyId));
			final Authentication authResult = this.authnManager.authenticate(authRequest);
			final SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
			context.setAuthentication(authResult);
			this.securityContextHolderStrategy.setContext(context);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
			}
			this.securityContextRepository.saveContext(context, request, response);
			if (this.successHandler != null) {
				this.successHandler.onAuthenticationSuccess(request, response, authRequest);
			}
		}
		catch (final AuthenticationException ex) {
			this.securityContextHolderStrategy.clearContext();
			this.logger.debug("Failed to process authentication request", ex);
			if (this.failureHandler != null) {
				this.failureHandler.onAuthenticationFailure(request, response, ex);
			}

			return;
		}

		filterChain.doFilter(request, response);
	}

}
