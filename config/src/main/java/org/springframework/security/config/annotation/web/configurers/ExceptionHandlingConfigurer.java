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
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FormPostRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.RequestMatcherDelegatingAccessDeniedHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

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
		if (this.defaultDeniedHandlerMappings.isEmpty()) {
			return new AuthenticationFactorDelegatingAccessDeniedHandler();
		}
		if (this.defaultDeniedHandlerMappings.size() == 1) {
			return this.defaultDeniedHandlerMappings.values().iterator().next();
		}
		return new RequestMatcherDelegatingAccessDeniedHandler(this.defaultDeniedHandlerMappings,
				new AuthenticationFactorDelegatingAccessDeniedHandler());
	}

	private AuthenticationEntryPoint createDefaultEntryPoint(H http) {
		if (this.defaultEntryPoint == null) {
			return new Http403ForbiddenEntryPoint();
		}
		return this.defaultEntryPoint.build();
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

	private static final class AuthenticationFactorDelegatingAccessDeniedHandler implements AccessDeniedHandler {

		private final Map<String, AuthenticationEntryPoint> entryPoints = Map.of("FACTOR_PASSWORD",
				new LoginUrlAuthenticationEntryPoint("/login"), "FACTOR_AUTHORIZATION_CODE",
				new LoginUrlAuthenticationEntryPoint("/login"), "FACTOR_SAML_RESPONSE",
				new LoginUrlAuthenticationEntryPoint("/login"), "FACTOR_WEBAUTHN",
				new LoginUrlAuthenticationEntryPoint("/login"), "FACTOR_BEARER",
				new BearerTokenAuthenticationEntryPoint(), "FACTOR_OTT",
				new PostAuthenticationEntryPoint(GenerateOneTimeTokenFilter.DEFAULT_GENERATE_URL + "?username={u}",
						Map.of("u", Authentication::getName)));

		private final AccessDeniedHandler defaults = new AccessDeniedHandlerImpl();

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex)
				throws IOException, ServletException {
			Collection<String> needed = authorizationRequest(ex);
			if (needed == null) {
				this.defaults.handle(request, response, ex);
				return;
			}
			for (String authority : needed) {
				AuthenticationEntryPoint entryPoint = this.entryPoints.get(authority);
				if (entryPoint != null) {
					AuthenticationException insufficient = new InsufficientAuthenticationException(ex.getMessage(), ex);
					entryPoint.commence(request, response, insufficient);
					return;
				}
			}
			this.defaults.handle(request, response, ex);
		}

		private Collection<String> authorizationRequest(AccessDeniedException access) {
			if (!(access instanceof AuthorizationDeniedException denied)) {
				return null;
			}
			if (!(denied.getAuthorizationResult() instanceof AuthorityAuthorizationDecision decision)) {
				return null;
			}
			return decision.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
		}

	}

	private static final class PostAuthenticationEntryPoint implements AuthenticationEntryPoint {

		private final String entryPointUri;

		private final Map<String, Function<Authentication, String>> params;

		private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

		private RedirectStrategy redirectStrategy = new FormPostRedirectStrategy();

		private PostAuthenticationEntryPoint(String entryPointUri,
				Map<String, Function<Authentication, String>> params) {
			this.entryPointUri = entryPointUri;
			this.params = params;
		}

		@Override
		public void commence(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException authException) throws IOException, ServletException {
			Authentication authentication = getAuthentication(authException);
			Assert.notNull(authentication, "could not find authentication in order to perform post");
			Map<String, String> params = this.params.entrySet()
				.stream()
				.collect(Collectors.toMap(Map.Entry::getKey, (entry) -> entry.getValue().apply(authentication)));
			UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(this.entryPointUri);
			CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
			if (csrf != null) {
				builder.queryParam(csrf.getParameterName(), csrf.getToken());
			}
			String entryPointUrl = builder.build(false).expand(params).toUriString();
			this.redirectStrategy.sendRedirect(request, response, entryPointUrl);
		}

		private Authentication getAuthentication(AuthenticationException authException) {
			Authentication authentication = authException.getAuthenticationRequest();
			if (authentication != null && authentication.isAuthenticated()) {
				return authentication;
			}
			authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
			if (authentication != null && authentication.isAuthenticated()) {
				return authentication;
			}
			return null;
		}

	}

}
