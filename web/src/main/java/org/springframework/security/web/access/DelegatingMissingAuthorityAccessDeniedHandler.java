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

package org.springframework.security.web.access;

import java.io.IOException;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AccessDeniedHandler} that adapts {@link AuthenticationEntryPoint}s based on
 * missing {@link GrantedAuthority}s. These authorities are specified in an
 * {@link AuthorityAuthorizationDecision} inside an {@link AuthorizationDeniedException}.
 *
 * <p>
 * This is helpful in adaptive authentication scenarios where an
 * {@link org.springframework.security.authorization.AuthorizationManager} indicates
 * additional authorities needed to access a given resource.
 * </p>
 *
 * <p>
 * For example, if an
 * {@link org.springframework.security.authorization.AuthorizationManager} states that to
 * access the home page, the user needs the {@code FACTOR_OTT} authority, then this
 * handler can be configured in the following way to redirect to the one-time-token login
 * page:
 * </p>
 *
 * <code>
 *     AccessDeniedHandler handler = DelegatingMissingAuthorityAccessDeniedHandler.builder()
 *         .addEntryPointFor(new LoginUrlAuthenticationEntryPoint("/login"), "FACTOR_OTT")
 *         .addEntryPointFor(new MyCustomEntryPoint(), "FACTOR_PASSWORD")
 *         .build();
 * </code>
 *
 * @author Josh Cummings
 * @since 7.0
 * @see AuthorizationDeniedException
 * @see AuthorityAuthorizationDecision
 * @see org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
 */
public final class DelegatingMissingAuthorityAccessDeniedHandler implements AccessDeniedHandler {

	private final ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();

	private final Map<String, AuthenticationEntryPoint> entryPoints;

	private RequestCache requestCache = new NullRequestCache();

	private AccessDeniedHandler defaultAccessDeniedHandler = new AccessDeniedHandlerImpl();

	private DelegatingMissingAuthorityAccessDeniedHandler(Map<String, AuthenticationEntryPoint> entryPoints) {
		Assert.notEmpty(entryPoints, "entryPoints cannot be empty");
		this.entryPoints = entryPoints;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException denied)
			throws IOException, ServletException {
		Collection<GrantedAuthority> authorities = missingAuthorities(denied);
		for (GrantedAuthority needed : authorities) {
			AuthenticationEntryPoint entryPoint = this.entryPoints.get(needed.getAuthority());
			if (entryPoint == null) {
				continue;
			}
			this.requestCache.saveRequest(request, response);
			request.setAttribute(WebAttributes.MISSING_AUTHORITIES, List.of(needed));
			String message = String.format("Missing Authorities %s", List.of(needed));
			AuthenticationException ex = new InsufficientAuthenticationException(message, denied);
			entryPoint.commence(request, response, ex);
			return;
		}
		this.defaultAccessDeniedHandler.handle(request, response, denied);
	}

	/**
	 * Use this {@link AccessDeniedHandler} for {@link AccessDeniedException}s that this
	 * handler doesn't support. By default, this uses {@link AccessDeniedHandlerImpl}.
	 * @param defaultAccessDeniedHandler the default {@link AccessDeniedHandler} to use
	 */
	public void setDefaultAccessDeniedHandler(AccessDeniedHandler defaultAccessDeniedHandler) {
		Assert.notNull(defaultAccessDeniedHandler, "defaultAccessDeniedHandler cannot be null");
		this.defaultAccessDeniedHandler = defaultAccessDeniedHandler;
	}

	/**
	 * Use this {@link RequestCache} to remember the current request.
	 * <p>
	 * Uses {@link NullRequestCache} by default
	 * </p>
	 * @param requestCache the {@link RequestCache} to use
	 */
	public void setRequestCache(RequestCache requestCache) {
		Assert.notNull(requestCache, "requestCachgrantedaue cannot be null");
		this.requestCache = requestCache;
	}

	private Collection<GrantedAuthority> missingAuthorities(AccessDeniedException ex) {
		AuthorizationDeniedException denied = findAuthorizationDeniedException(ex);
		if (denied == null) {
			return List.of();
		}
		if (!(denied.getAuthorizationResult() instanceof AuthorityAuthorizationDecision authorization)) {
			return List.of();
		}
		return authorization.getAuthorities();
	}

	private @Nullable AuthorizationDeniedException findAuthorizationDeniedException(AccessDeniedException ex) {
		if (ex instanceof AuthorizationDeniedException denied) {
			return denied;
		}
		Throwable[] chain = this.throwableAnalyzer.determineCauseChain(ex);
		return (AuthorizationDeniedException) this.throwableAnalyzer
			.getFirstThrowableOfType(AuthorizationDeniedException.class, chain);
	}

	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for configuring the set of authority/entry-point pairs
	 *
	 * @author Josh Cummings
	 * @since 7.0
	 */
	public static final class Builder {

		private final Map<String, DelegatingAuthenticationEntryPoint.Builder> entryPointBuilderByAuthority = new LinkedHashMap<>();

		private Builder() {

		}

		/**
		 * Use this {@link AuthenticationEntryPoint} when the given
		 * {@code missingAuthority} is missing from the authenticated user
		 * @param entryPoint the {@link AuthenticationEntryPoint} for the given authority
		 * @param missingAuthority the authority
		 * @return the {@link Builder} for further configurations
		 */
		public Builder addEntryPointFor(AuthenticationEntryPoint entryPoint, String missingAuthority) {
			DelegatingAuthenticationEntryPoint.Builder builder = DelegatingAuthenticationEntryPoint.builder()
				.addEntryPointFor(entryPoint, AnyRequestMatcher.INSTANCE);
			this.entryPointBuilderByAuthority.put(missingAuthority, builder);
			return this;
		}

		/**
		 * Use this {@link AuthenticationEntryPoint} when the given
		 * {@code missingAuthority} is missing from the authenticated user
		 * @param entryPoint a consumer to configure the underlying
		 * {@link DelegatingAuthenticationEntryPoint}
		 * @param missingAuthority the authority
		 * @return the {@link Builder} for further configurations
		 */
		public Builder addEntryPointFor(Consumer<DelegatingAuthenticationEntryPoint.Builder> entryPoint,
				String missingAuthority) {
			entryPoint.accept(this.entryPointBuilderByAuthority.computeIfAbsent(missingAuthority,
					(k) -> DelegatingAuthenticationEntryPoint.builder()));
			return this;
		}

		public DelegatingMissingAuthorityAccessDeniedHandler build() {
			Map<String, AuthenticationEntryPoint> entryPointByAuthority = new LinkedHashMap<>();
			this.entryPointBuilderByAuthority.forEach((key, value) -> entryPointByAuthority.put(key, value.build()));
			return new DelegatingMissingAuthorityAccessDeniedHandler(entryPointByAuthority);
		}

	}

}
