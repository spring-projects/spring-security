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
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

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
 *         .authorities("FACTOR_OTT").commence(new LoginUrlAuthenticationEntryPoint("/login"))
 *         .authorities("FACTOR_PASSWORD")...
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
		this.entryPoints = entryPoints;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException denied)
			throws IOException, ServletException {
		Collection<GrantedAuthority> authorities = missingAuthorities(denied);
		AuthenticationEntryPoint entryPoint = entryPoint(authorities);
		if (entryPoint == null) {
			this.defaultAccessDeniedHandler.handle(request, response, denied);
			return;
		}
		this.requestCache.saveRequest(request, response);
		AuthenticationException ex = new InsufficientAuthenticationException("missing authorities", denied);
		entryPoint.commence(request, response, ex);
	}

	/**
	 * Use this {@link AccessDeniedHandler} for {@link AccessDeniedException}s that this
	 * handler doesn't support. By default, this uses {@link AccessDeniedHandlerImpl}.
	 * @param defaultAccessDeniedHandler the default {@link AccessDeniedHandler} to use
	 */
	public void setDefaultAccessDeniedHandler(AccessDeniedHandler defaultAccessDeniedHandler) {
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
		this.requestCache = requestCache;
	}

	private @Nullable AuthenticationEntryPoint entryPoint(Collection<GrantedAuthority> authorities) {
		for (GrantedAuthority needed : authorities) {
			AuthenticationEntryPoint entryPoint = this.entryPoints.get(needed.getAuthority());
			if (entryPoint == null) {
				continue;
			}
			return entryPoint;
		}
		return null;
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

		private final Map<String, DelegatingAuthenticationEntryPoint.Builder> entryPointByRequestMatcherByAuthority = new LinkedHashMap<>();

		private Builder() {

		}

		DelegatingAuthenticationEntryPoint.Builder entryPointBuilder(String authority) {
			return this.entryPointByRequestMatcherByAuthority.computeIfAbsent(authority,
					(k) -> DelegatingAuthenticationEntryPoint.builder());
		}

		void entryPoint(String authority, AuthenticationEntryPoint entryPoint) {
			DelegatingAuthenticationEntryPoint.Builder builder = DelegatingAuthenticationEntryPoint.builder()
				.addEntryPointFor(entryPoint, AnyRequestMatcher.INSTANCE);
			this.entryPointByRequestMatcherByAuthority.put(authority, builder);
		}

		/**
		 * Bind these authorities to the given {@link AuthenticationEntryPoint}
		 * @param entryPoint the {@link AuthenticationEntryPoint} for the given
		 * authorities
		 * @param authorities the authorities
		 * @return the {@link Builder} for further configurations
		 */
		public Builder addEntryPointFor(AuthenticationEntryPoint entryPoint, String... authorities) {
			for (String authority : authorities) {
				Builder.this.entryPoint(authority, entryPoint);
			}
			return this;
		}

		/**
		 * Bind these authorities to the given {@link AuthenticationEntryPoint}
		 * @param entryPoint a consumer to configure the underlying
		 * {@link DelegatingAuthenticationEntryPoint}
		 * @param authorities the authorities
		 * @return the {@link Builder} for further configurations
		 */
		public Builder addEntryPointFor(Consumer<DelegatingAuthenticationEntryPoint.Builder> entryPoint,
				String... authorities) {
			for (String authority : authorities) {
				entryPoint.accept(Builder.this.entryPointBuilder(authority));
			}
			return this;
		}

		public DelegatingMissingAuthorityAccessDeniedHandler build() {
			Map<String, AuthenticationEntryPoint> entryPointByAuthority = new LinkedHashMap<>();
			for (String authority : this.entryPointByRequestMatcherByAuthority.keySet()) {
				entryPointByAuthority.put(authority, this.entryPointByRequestMatcherByAuthority.get(authority).build());
			}
			return new DelegatingMissingAuthorityAccessDeniedHandler(entryPointByAuthority);
		}

	}

}
