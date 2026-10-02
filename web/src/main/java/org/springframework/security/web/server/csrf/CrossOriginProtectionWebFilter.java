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

package org.springframework.security.web.server.csrf;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;
import reactor.core.publisher.Mono;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

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
 * {@link CorsUtils#isCorsRequest(ServerHttpRequest)}, and rejected otherwise. Behind a
 * proxy, configure forwarded headers so that the request reflects its public origin.</li>
 * <li>Otherwise the request did not come from a browser, or from one too old to send
 * either header, and is allowed.</li>
 * </ol>
 * A request whose {@code Origin} is one of the {@link #setTrustedOrigins(Collection)
 * trusted origins} is allowed in all cases. A rejected request is passed to the
 * {@link ServerAccessDeniedHandler} with a {@link CrossOriginRequestException}; in
 * {@link #setReportOnly(boolean) report-only} mode it is logged and allowed instead.
 *
 * <p>
 * Unlike {@link CsrfWebFilter}, this filter keeps no state: it neither creates nor reads
 * a session, and a request needs nothing added to it, so a form or request already on a
 * page cannot become invalid because the session expired or was replaced. Requests from
 * non-browser clients need no exemption, since they send neither header.
 *
 * <p>
 * An exchange marked with {@link CsrfWebFilter#skipExchange(ServerWebExchange)} is not
 * checked.
 *
 * @author Scott Murphy Heiberg
 * @since 7.2
 * @see <a href="https://web.dev/articles/fetch-metadata">Protect your resources from web
 * attacks with Fetch Metadata</a>
 */
public final class CrossOriginProtectionWebFilter implements WebFilter {

	private static final String SEC_FETCH_SITE = "Sec-Fetch-Site";

	private final Log logger = LogFactory.getLog(getClass());

	private ServerWebExchangeMatcher requireProtectionMatcher = CsrfWebFilter.DEFAULT_CSRF_MATCHER;

	private ServerAccessDeniedHandler accessDeniedHandler = new HttpStatusServerAccessDeniedHandler(
			HttpStatus.FORBIDDEN);

	private @Nullable CorsConfiguration trustedOrigins;

	private boolean reportOnly;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		if (CsrfWebFilter.isSkipped(exchange)) {
			return chain.filter(exchange);
		}
		return this.requireProtectionMatcher.matches(exchange).flatMap((match) -> {
			String rejection = match.isMatch() ? rejection(exchange.getRequest()) : null;
			if (rejection == null) {
				return chain.filter(exchange);
			}
			if (this.reportOnly) {
				this.logger.warn(LogMessage.format("Would have rejected cross-origin request %s %s (%s)",
						exchange.getRequest().getMethod(), exchange.getRequest().getPath(), rejection));
				return chain.filter(exchange);
			}
			this.logger.debug(LogMessage.of(() -> "Rejected cross-origin request to " + exchange.getRequest().getURI()
					+ " (" + rejection + ")"));
			return this.accessDeniedHandler.handle(exchange,
					new CrossOriginRequestException("Cross-origin request rejected: " + rejection));
		});
	}

	private @Nullable String rejection(ServerHttpRequest request) {
		String site = request.getHeaders().getFirst(SEC_FETCH_SITE);
		if (StringUtils.hasText(site)) {
			if ("same-origin".equals(site) || "none".equals(site) || isTrusted(request)) {
				return null;
			}
			return "Sec-Fetch-Site is " + site;
		}
		String origin = request.getHeaders().getOrigin();
		if (origin == null || !isCrossOrigin(request) || isTrusted(request)) {
			return null;
		}
		return "Origin " + origin + " is not the origin of the request";
	}

	private static boolean isCrossOrigin(ServerHttpRequest request) {
		try {
			return CorsUtils.isCorsRequest(request);
		}
		catch (IllegalArgumentException ex) {
			// an Origin that cannot be parsed is not this application's
			return true;
		}
	}

	private boolean isTrusted(ServerHttpRequest request) {
		return this.trustedOrigins != null && this.trustedOrigins.checkOrigin(request.getHeaders().getOrigin()) != null;
	}

	/**
	 * Specifies the {@link ServerWebExchangeMatcher} used to determine which requests are
	 * protected. The default is {@link CsrfWebFilter#DEFAULT_CSRF_MATCHER}, which
	 * protects every request whose method is not GET, HEAD, TRACE or OPTIONS.
	 * @param requireProtectionMatcher the {@link ServerWebExchangeMatcher} to use
	 */
	public void setRequireProtectionMatcher(ServerWebExchangeMatcher requireProtectionMatcher) {
		Assert.notNull(requireProtectionMatcher, "requireProtectionMatcher cannot be null");
		this.requireProtectionMatcher = requireProtectionMatcher;
	}

	/**
	 * Specifies the {@link ServerAccessDeniedHandler} used when a request is rejected.
	 * The default responds with {@link HttpStatus#FORBIDDEN}.
	 * @param accessDeniedHandler the {@link ServerAccessDeniedHandler} to use
	 */
	public void setAccessDeniedHandler(ServerAccessDeniedHandler accessDeniedHandler) {
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

	/**
	 * Specifies whether a request that would be rejected is only logged, at WARN level,
	 * and allowed. This shows what the protection would reject before it is enforced, for
	 * example while finding the origins to trust. The default is {@code false}.
	 * @param reportOnly {@code true} to log rejections instead of enforcing them
	 */
	public void setReportOnly(boolean reportOnly) {
		this.reportOnly = reportOnly;
	}

}
