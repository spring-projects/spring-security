/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@link Filter} that performs authentication of a particular request. An
 * outline of the logic:
 *
 * <ul>
 * <li>A request comes in and if it does not match
 * {@link #setRequestMatcher(RequestMatcher)}, then this filter does nothing and
 * the {@link FilterChain} is continued. If it does match then...</li>
 * <li>An attempt to convert the {@link HttpServletRequest} into an
 * {@link Authentication} is made. If the result is empty, then the filter does
 * nothing more and the {@link FilterChain} is continued. If it does create an
 * {@link Authentication}...</li>
 * <li>The {@link AuthenticationManager} specified in
 * {@link #GenericAuthenticationFilter(AuthenticationManager)} is used to
 * perform authentication.</li>
 * <li>The {@link AuthenticationManagerResolver} specified in
 * {@link #GenericAuthenticationFilter(AuthenticationManagerResolver)} is used
 * to resolve the appropriate authentication manager from context to perform
 * authentication.</li>
 * <li>If authentication is successful, {@link AuthenticationSuccessHandler} is
 * invoked and the authentication is set on {@link SecurityContextHolder}, else
 * {@link AuthenticationFailureHandler} is invoked</li>
 * </ul>
 *
 * @author Sergey Bespalov
 * @since 5.2.0
 */
public class AuthenticationFilter extends OncePerRequestFilter {

	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;
	private AuthenticationConverter authenticationConverter;
	private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
	private AuthenticationFailureHandler failureHandler = new AuthenticationEntryPointFailureHandler(
			new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
	private AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	public AuthenticationFilter(AuthenticationManager authenticationManager,
			AuthenticationConverter authenticationConverter) {
		this((AuthenticationManagerResolver<HttpServletRequest>) r -> authenticationManager, authenticationConverter);
	}

	public AuthenticationFilter(AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver,
			AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");

		this.authenticationManagerResolver = authenticationManagerResolver;
		this.authenticationConverter = authenticationConverter;
	}

	public RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	public AuthenticationConverter getAuthenticationConverter() {
		return this.authenticationConverter;
	}

	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	public AuthenticationSuccessHandler getSuccessHandler() {
		return this.successHandler;
	}

	public void setSuccessHandler(AuthenticationSuccessHandler successHandler) {
		Assert.notNull(successHandler, "successHandler cannot be null");
		this.successHandler = successHandler;
	}

	public AuthenticationFailureHandler getFailureHandler() {
		return this.failureHandler;
	}

	public void setFailureHandler(AuthenticationFailureHandler failureHandler) {
		Assert.notNull(failureHandler, "failureHandler cannot be null");
		this.failureHandler = failureHandler;
	}

	public AuthenticationManagerResolver<HttpServletRequest> getAuthenticationManagerResolver() {
		return this.authenticationManagerResolver;
	}

	public void setAuthenticationManagerResolver(
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
		Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");
		this.authenticationManagerResolver = authenticationManagerResolver;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication authenticationResult = attemptAuthentication(request, response);
			if (authenticationResult == null) {
				filterChain.doFilter(request, response);
				return;
			}

			successfulAuthentication(request, response, filterChain, authenticationResult);
		} catch (AuthenticationException e) {
			unsuccessfulAuthentication(request, response, e);
		}
	}

	private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		this.failureHandler.onAuthenticationFailure(request, response, failed);
	}

	private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authentication) throws IOException, ServletException {
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		SecurityContextHolder.setContext(context);
		this.successHandler.onAuthenticationSuccess(request, response, chain, authentication);
	}

	private Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		Authentication authentication = this.authenticationConverter.convert(request);
		if (authentication == null) {
			return null;
		}

		AuthenticationManager authenticationManager = this.authenticationManagerResolver.resolve(request);
		Authentication authenticationResult = authenticationManager.authenticate(authentication);
		if (authenticationResult == null) {
			throw new ServletException("AuthenticationManager should not return null Authentication object.");
		}

		return authenticationResult;
	}

}
