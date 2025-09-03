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

package org.springframework.security.config.annotation.web.configurers;

import java.io.IOException;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.RequestMatcherDelegatingAccessDeniedHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Adds exception handling for Spring Security related exceptions to an application. All
 * properties have reasonable defaults, so no additional configuration is required other
 * than applying this
 * {@link org.springframework.security.config.annotation.SecurityConfigurer}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link ExceptionTranslationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>If no explicit {@link RequestCache}, is provided a {@link RequestCache} shared
 * object is used to replay the request after authentication is successful</li>
 * <li>{@link AuthenticationEntryPoint} - see
 * {@link #authenticationEntryPoint(AuthenticationEntryPoint)}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class ExceptionHandlingConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<ExceptionHandlingConfigurer<H>, H> {

	private AuthenticationEntryPoint authenticationEntryPoint;

	private AccessDeniedHandler accessDeniedHandler;

	private DelegatingAuthenticationEntryPoint.@Nullable Builder defaultEntryPoint;

	private LinkedHashMap<RequestMatcher, AccessDeniedHandler> defaultDeniedHandlerMappings = new LinkedHashMap<>();

	private Map<String, LinkedHashMap<RequestMatcher, AuthenticationEntryPoint>> entryPoints = new LinkedHashMap<>();

	/**
	 * Creates a new instance
	 * @see HttpSecurity#exceptionHandling(Customizer)
	 */
	public ExceptionHandlingConfigurer() {
	}

	/**
	 * Shortcut to specify the {@link AccessDeniedHandler} to be used is a specific error
	 * page
	 * @param accessDeniedUrl the URL to the access denied page (i.e. /errors/401)
	 * @return the {@link ExceptionHandlingConfigurer} for further customization
	 * @see AccessDeniedHandlerImpl
	 * @see #accessDeniedHandler(org.springframework.security.web.access.AccessDeniedHandler)
	 */
	public ExceptionHandlingConfigurer<H> accessDeniedPage(String accessDeniedUrl) {
		AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
		accessDeniedHandler.setErrorPage(accessDeniedUrl);
		return accessDeniedHandler(accessDeniedHandler);
	}

	/**
	 * Specifies the {@link AccessDeniedHandler} to be used
	 * @param accessDeniedHandler the {@link AccessDeniedHandler} to be used
	 * @return the {@link ExceptionHandlingConfigurer} for further customization
	 */
	public ExceptionHandlingConfigurer<H> accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		this.accessDeniedHandler = accessDeniedHandler;
		return this;
	}

	/**
	 * Sets a default {@link AccessDeniedHandler} to be used which prefers being invoked
	 * for the provided {@link RequestMatcher}. If only a single default
	 * {@link AccessDeniedHandler} is specified, it will be what is used for the default
	 * {@link AccessDeniedHandler}. If multiple default {@link AccessDeniedHandler}
	 * instances are configured, then a
	 * {@link RequestMatcherDelegatingAccessDeniedHandler} will be used.
	 * @param deniedHandler the {@link AccessDeniedHandler} to use
	 * @param preferredMatcher the {@link RequestMatcher} for this default
	 * {@link AccessDeniedHandler}
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 * @since 5.1
	 */
	public ExceptionHandlingConfigurer<H> defaultAccessDeniedHandlerFor(AccessDeniedHandler deniedHandler,
			RequestMatcher preferredMatcher) {
		this.defaultDeniedHandlerMappings.put(preferredMatcher, deniedHandler);
		return this;
	}

	/**
	 * Sets the {@link AuthenticationEntryPoint} to be used.
	 *
	 * <p>
	 * If no {@link #authenticationEntryPoint(AuthenticationEntryPoint)} is specified,
	 * then
	 * {@link #defaultAuthenticationEntryPointFor(AuthenticationEntryPoint, RequestMatcher)}
	 * will be used. The first {@link AuthenticationEntryPoint} will be used as the
	 * default if no matches were found.
	 * </p>
	 *
	 * <p>
	 * If that is not provided defaults to {@link Http403ForbiddenEntryPoint}.
	 * </p>
	 * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 */
	public ExceptionHandlingConfigurer<H> authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		return this;
	}

	/**
	 * Sets a default {@link AuthenticationEntryPoint} to be used which prefers being
	 * invoked for the provided {@link RequestMatcher}. If only a single default
	 * {@link AuthenticationEntryPoint} is specified, it will be what is used for the
	 * default {@link AuthenticationEntryPoint}. If multiple default
	 * {@link AuthenticationEntryPoint} instances are configured, then a
	 * {@link DelegatingAuthenticationEntryPoint} will be used.
	 * @param entryPoint the {@link AuthenticationEntryPoint} to use
	 * @param preferredMatcher the {@link RequestMatcher} for this default
	 * {@link AuthenticationEntryPoint}
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 */
	public ExceptionHandlingConfigurer<H> defaultAuthenticationEntryPointFor(AuthenticationEntryPoint entryPoint,
			RequestMatcher preferredMatcher) {
		if (this.defaultEntryPoint == null) {
			this.defaultEntryPoint = DelegatingAuthenticationEntryPoint.builder();
		}
		this.defaultEntryPoint.addEntryPointFor(entryPoint, preferredMatcher);
		return this;
	}

	public ExceptionHandlingConfigurer<H> defaultAuthenticationEntryPointFor(AuthenticationEntryPoint entryPoint,
			RequestMatcher preferredMatcher, String authority) {
		this.defaultEntryPointMappings.put(preferredMatcher, entryPoint);
		LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> byMatcher = this.entryPoints.get(authority);
		if (byMatcher == null) {
			byMatcher = new LinkedHashMap<>();
		}
		byMatcher.put(preferredMatcher, entryPoint);
		this.entryPoints.put(authority, byMatcher);
		return this;
	}

	public ExceptionHandlingConfigurer<H> defaultAuthenticationEntryPointFor(AuthenticationEntryPoint entryPoint,
			String authority) {
		LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> byMatcher = new LinkedHashMap<>();
		byMatcher.put(AnyRequestMatcher.INSTANCE, entryPoint);
		this.entryPoints.put(authority, byMatcher);
		return this;
	}

	/**
	 * Gets any explicitly configured {@link AuthenticationEntryPoint}
	 * @return
	 */
	AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return this.authenticationEntryPoint;
	}

	/**
	 * Gets the {@link AccessDeniedHandler} that is configured.
	 * @return the {@link AccessDeniedHandler}
	 */
	AccessDeniedHandler getAccessDeniedHandler() {
		return this.accessDeniedHandler;
	}

	@Override
	public void configure(H http) {
		AuthenticationEntryPoint entryPoint = getAuthenticationEntryPoint(http);
		ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(entryPoint,
				getRequestCache(http));
		AccessDeniedHandler deniedHandler = getAccessDeniedHandler(http);
		exceptionTranslationFilter.setAccessDeniedHandler(deniedHandler);
		exceptionTranslationFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		exceptionTranslationFilter = postProcess(exceptionTranslationFilter);
		http.addFilter(exceptionTranslationFilter);
	}

	/**
	 * Gets the {@link AccessDeniedHandler} according to the rules specified by
	 * {@link #accessDeniedHandler(AccessDeniedHandler)}
	 * @param http the {@link HttpSecurity} used to look up shared
	 * {@link AccessDeniedHandler}
	 * @return the {@link AccessDeniedHandler} to use
	 */
	AccessDeniedHandler getAccessDeniedHandler(H http) {
		AccessDeniedHandler deniedHandler = this.accessDeniedHandler;
		if (deniedHandler == null) {
			deniedHandler = createDefaultDeniedHandler(http);
		}
		return deniedHandler;
	}

	/**
	 * Gets the {@link AuthenticationEntryPoint} according to the rules specified by
	 * {@link #authenticationEntryPoint(AuthenticationEntryPoint)}
	 * @param http the {@link HttpSecurity} used to look up shared
	 * {@link AuthenticationEntryPoint}
	 * @return the {@link AuthenticationEntryPoint} to use
	 */
	AuthenticationEntryPoint getAuthenticationEntryPoint(H http) {
		AuthenticationEntryPoint entryPoint = this.authenticationEntryPoint;
		if (entryPoint == null) {
			entryPoint = createDefaultEntryPoint(http);
		}
		return entryPoint;
	}

	private AccessDeniedHandler createDefaultDeniedHandler(H http) {
		AccessDeniedHandler defaults = createDefaultAccessDeniedHandler(http);
		if (this.entryPoints.isEmpty()) {
			return defaults;
		}
		Map<String, AccessDeniedHandler> deniedHandlers = new LinkedHashMap<>();
		for (Map.Entry<String, LinkedHashMap<RequestMatcher, AuthenticationEntryPoint>> entry : this.entryPoints
			.entrySet()) {
			AuthenticationEntryPoint entryPoint = entryPointFrom(entry.getValue());
			AuthenticationEntryPointAccessDeniedHandlerAdapter deniedHandler = new AuthenticationEntryPointAccessDeniedHandlerAdapter(
					entryPoint);
			RequestCache requestCache = http.getSharedObject(RequestCache.class);
			if (requestCache != null) {
				deniedHandler.setRequestCache(requestCache);
			}
			deniedHandlers.put(entry.getKey(), deniedHandler);
		}
		return new AuthenticationFactorDelegatingAccessDeniedHandler(deniedHandlers, defaults);
	}

	private AccessDeniedHandler createDefaultAccessDeniedHandler(H http) {
		if (this.defaultDeniedHandlerMappings.isEmpty()) {
			return new AccessDeniedHandlerImpl();
		}
		if (this.defaultDeniedHandlerMappings.size() == 1) {
			return this.defaultDeniedHandlerMappings.values().iterator().next();
		}
		return new RequestMatcherDelegatingAccessDeniedHandler(this.defaultDeniedHandlerMappings,
				new AccessDeniedHandlerImpl());
	}

	private AuthenticationEntryPoint createDefaultEntryPoint(H http) {
		AuthenticationEntryPoint defaults = entryPointFrom(this.defaultEntryPointMappings);
		if (this.entryPoints.isEmpty()) {
			return defaults;
		}
		Map<String, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
		for (Map.Entry<String, LinkedHashMap<RequestMatcher, AuthenticationEntryPoint>> entry : this.entryPoints
			.entrySet()) {
			entryPoints.put(entry.getKey(), entryPointFrom(entry.getValue()));
		}
		return new AuthenticationFactorDelegatingAuthenticationEntryPoint(entryPoints, defaults);
	}

	private AuthenticationEntryPoint entryPointFrom(
			LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints) {
		if (entryPoints.isEmpty()) {
			return new Http403ForbiddenEntryPoint();
		}
		if (entryPoints.size() == 1) {
			return entryPoints.values().iterator().next();
		}
		DelegatingAuthenticationEntryPoint entryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
		entryPoint.setDefaultEntryPoint(entryPoints.values().iterator().next());
		return entryPoint;
	}

	/**
	 * Gets the {@link RequestCache} to use. If one is defined using
	 * {@link #requestCache(org.springframework.security.web.savedrequest.RequestCache)},
	 * then it is used. Otherwise, an attempt to find a {@link RequestCache} shared object
	 * is made. If that fails, an {@link HttpSessionRequestCache} is used
	 * @param http the {@link HttpSecurity} to attempt to fined the shared object
	 * @return the {@link RequestCache} to use
	 */
	private RequestCache getRequestCache(H http) {
		RequestCache result = http.getSharedObject(RequestCache.class);
		if (result != null) {
			return result;
		}
		return new HttpSessionRequestCache();
	}

	private static final class AuthenticationFactorDelegatingAuthenticationEntryPoint
			implements AuthenticationEntryPoint {

		private final ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();

		private final Map<String, AuthenticationEntryPoint> entryPoints;

		private final AuthenticationEntryPoint defaults;

		private AuthenticationFactorDelegatingAuthenticationEntryPoint(
				Map<String, AuthenticationEntryPoint> entryPoints, AuthenticationEntryPoint defaults) {
			this.entryPoints = new LinkedHashMap<>(entryPoints);
			this.defaults = defaults;
		}

		@Override
		public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
				throws IOException, ServletException {
			Collection<GrantedAuthority> authorization = authorizationRequest(ex);
			entryPoint(authorization).commence(request, response, ex);
		}

		private AuthenticationEntryPoint entryPoint(Collection<GrantedAuthority> authorities) {
			if (authorities == null) {
				return this.defaults;
			}
			for (GrantedAuthority needed : authorities) {
				AuthenticationEntryPoint entryPoint = this.entryPoints.get(needed.getAuthority());
				if (entryPoint != null) {
					return entryPoint;
				}
			}
			return this.defaults;
		}

		private Collection<GrantedAuthority> authorizationRequest(Exception ex) {
			Throwable[] chain = this.throwableAnalyzer.determineCauseChain(ex);
			AuthorizationDeniedException denied = (AuthorizationDeniedException) this.throwableAnalyzer
				.getFirstThrowableOfType(AuthorizationDeniedException.class, chain);
			if (denied == null) {
				return List.of();
			}
			if (!(denied.getAuthorizationResult() instanceof AuthorityAuthorizationDecision authorization)) {
				return List.of();
			}
			return authorization.getAuthorities();
		}

	}

	private static final class AuthenticationEntryPointAccessDeniedHandlerAdapter implements AccessDeniedHandler {

		private final AuthenticationEntryPoint entryPoint;

		private RequestCache requestCache = new NullRequestCache();

		private AuthenticationEntryPointAccessDeniedHandlerAdapter(AuthenticationEntryPoint entryPoint) {
			this.entryPoint = entryPoint;
		}

		void setRequestCache(RequestCache requestCache) {
			Assert.notNull(requestCache, "requestCache cannot be null");
			this.requestCache = requestCache;
		}

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException denied)
				throws IOException, ServletException {
			AuthenticationException ex = new InsufficientAuthenticationException("access denied", denied);
			this.requestCache.saveRequest(request, response);
			this.entryPoint.commence(request, response, ex);
		}

	}

	private static final class AuthenticationFactorDelegatingAccessDeniedHandler implements AccessDeniedHandler {

		private final ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();

		private final Map<String, AccessDeniedHandler> deniedHandlers;

		private final AccessDeniedHandler defaults;

		private AuthenticationFactorDelegatingAccessDeniedHandler(Map<String, AccessDeniedHandler> deniedHandlers,
				AccessDeniedHandler defaults) {
			this.deniedHandlers = new LinkedHashMap<>(deniedHandlers);
			this.defaults = defaults;
		}

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex)
				throws IOException, ServletException {
			Collection<GrantedAuthority> authorization = authorizationRequest(ex);
			deniedHandler(authorization).handle(request, response, ex);
		}

		private AccessDeniedHandler deniedHandler(Collection<GrantedAuthority> authorities) {
			if (authorities == null) {
				return this.defaults;
			}
			for (GrantedAuthority needed : authorities) {
				AccessDeniedHandler deniedHandler = this.deniedHandlers.get(needed.getAuthority());
				if (deniedHandler != null) {
					return deniedHandler;
				}
			}
			return this.defaults;
		}

		private Collection<GrantedAuthority> authorizationRequest(Exception ex) {
			Throwable[] chain = this.throwableAnalyzer.determineCauseChain(ex);
			AuthorizationDeniedException denied = (AuthorizationDeniedException) this.throwableAnalyzer
				.getFirstThrowableOfType(AuthorizationDeniedException.class, chain);
			if (denied == null) {
				return List.of();
			}
			if (!(denied.getAuthorizationResult() instanceof AuthorityAuthorizationDecision authorization)) {
				return List.of();
			}
			return authorization.getAuthorities();
		}

	}

}
