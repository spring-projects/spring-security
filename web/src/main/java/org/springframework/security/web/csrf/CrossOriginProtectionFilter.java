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

package org.springframework.security.web.csrf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Applies <a href="https://owasp.org/www-community/attacks/csrf">CSRF</a> protection by
 * rejecting a state-changing request that the browser reports as coming from another
 * origin, instead of requiring a token.
 *
 * <p>
 * A request that requires protection (by default, any method other than GET, HEAD, TRACE
 * and OPTIONS) is checked as follows:
 * <ol>
 * <li>If the request has a <a href=
 * "https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site">{@code Sec-Fetch-Site}</a>
 * header, which all major browsers send, it is allowed when the value is
 * {@code same-origin} or {@code none} (a navigation the user started, such as a
 * bookmark), and rejected otherwise ({@code same-site} or {@code cross-site}).</li>
 * <li>Otherwise, if the request has an {@code Origin} header, as older browsers send, it
 * is allowed when that origin is the request's own, as determined by
 * {@link CorsUtils#isCorsRequest(HttpServletRequest)}, and rejected otherwise. Behind a
 * proxy, configure forwarded headers so that the request reflects its public origin.</li>
 * <li>Otherwise the request did not come from a browser, or from one too old to send
 * either header, and is allowed.</li>
 * </ol>
 * A request whose {@code Origin} is one of the {@link #setTrustedOrigins(Collection)
 * trusted origins} is allowed in all cases.
 *
 * <p>
 * Unlike {@link CsrfFilter}, this filter keeps no state: it neither creates nor reads a
 * session, and a request needs nothing added to it, so a form or request already on a
 * page cannot become invalid because the session expired or was replaced. Requests from
 * non-browser clients need no exemption, since they send neither header.
 *
 * <p>
 * A request marked with {@link CsrfFilter#skipRequest(HttpServletRequest)} is not
 * checked.
 *
 * @author Scott Murphy Heiberg
 * @since 7.2
 * @see <a href="https://web.dev/articles/fetch-metadata">Protect your resources from web
 * attacks with Fetch Metadata</a>
 */
public final class CrossOriginProtectionFilter extends OncePerRequestFilter {

	private static final String SEC_FETCH_SITE = "Sec-Fetch-Site";

	private final Log logger = LogFactory.getLog(getClass());

	private RequestMatcher requireProtectionMatcher = CsrfFilter.DEFAULT_CSRF_MATCHER;

	private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();

	private @Nullable CorsConfiguration trustedOrigins;

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		return CsrfFilter.isSkipped(request);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.requireProtectionMatcher.matches(request)) {
			if (this.logger.isTraceEnabled()) {
				this.logger
					.trace("Did not protect against CSRF since request did not match " + this.requireProtectionMatcher);
			}
			filterChain.doFilter(request, response);
			return;
		}
		String rejection = rejection(request);
		if (rejection == null) {
			filterChain.doFilter(request, response);
			return;
		}
		this.logger.debug(LogMessage.of(() -> "Rejected cross-origin request to "
				+ UrlUtils.buildFullRequestUrl(request) + " (" + rejection + ")"));
		this.accessDeniedHandler.handle(request, response,
				new CsrfException("Cross-origin request rejected: " + rejection));
	}

	private @Nullable String rejection(HttpServletRequest request) {
		String site = request.getHeader(SEC_FETCH_SITE);
		if (StringUtils.hasText(site)) {
			if ("same-origin".equals(site) || "none".equals(site) || isTrusted(request)) {
				return null;
			}
			return "Sec-Fetch-Site is " + site;
		}
		String origin = request.getHeader(HttpHeaders.ORIGIN);
		if (origin == null || !isCrossOrigin(request) || isTrusted(request)) {
			return null;
		}
		return "Origin " + origin + " is not the origin of the request";
	}

	private static boolean isCrossOrigin(HttpServletRequest request) {
		try {
			return CorsUtils.isCorsRequest(request);
		}
		catch (IllegalArgumentException ex) {
			// an Origin that cannot be parsed is not this application's
			return true;
		}
	}

	private boolean isTrusted(HttpServletRequest request) {
		return this.trustedOrigins != null
				&& this.trustedOrigins.checkOrigin(request.getHeader(HttpHeaders.ORIGIN)) != null;
	}

	/**
	 * Specifies the {@link RequestMatcher} used to determine which requests are
	 * protected. The default is {@link CsrfFilter#DEFAULT_CSRF_MATCHER}, which protects
	 * every request whose method is not GET, HEAD, TRACE or OPTIONS.
	 * @param requireProtectionMatcher the {@link RequestMatcher} to use
	 */
	public void setRequireProtectionMatcher(RequestMatcher requireProtectionMatcher) {
		Assert.notNull(requireProtectionMatcher, "requireProtectionMatcher cannot be null");
		this.requireProtectionMatcher = requireProtectionMatcher;
	}

	/**
	 * Specifies the {@link AccessDeniedHandler} used when a request is rejected. The
	 * default is an {@link AccessDeniedHandlerImpl} with no arguments.
	 * @param accessDeniedHandler the {@link AccessDeniedHandler} to use
	 */
	public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
		this.accessDeniedHandler = accessDeniedHandler;
	}

	/**
	 * Specifies origins whose requests are allowed even though they come from another
	 * origin, for example another application that posts to this one by design. Each is
	 * written as a browser sends it in the {@code Origin} header, such as
	 * {@code https://example.com}, and is matched as
	 * {@link CorsConfiguration#checkOrigin(String)} matches allowed origins.
	 * @param trustedOrigins the origins to trust
	 */
	public void setTrustedOrigins(Collection<String> trustedOrigins) {
		Assert.notNull(trustedOrigins, "trustedOrigins cannot be null");
		Assert.isTrue(!trustedOrigins.contains(CorsConfiguration.ALL),
				"trustedOrigins cannot contain \"*\", which would trust every origin");
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(new ArrayList<>(trustedOrigins));
		this.trustedOrigins = trustedOrigins.isEmpty() ? null : configuration;
	}

}
