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

package org.springframework.security.web.server.header;

import java.util.List;

import org.jspecify.annotations.Nullable;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.security.web.header.ContentSecurityPolicyNonce;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Writes the {@code Content-Security-Policy} response header with configured policy
 * directives.
 *
 * <p>
 * With related directives specified, web clients could block inline {@code <script>} or
 * {@code <style>} blocks in the HTML to mitigate XSS attacks injecting malicious inline
 * blocks. To allow intended inline blocks, a CSP directive (usually {@code script-src} or
 * {@code style-src}) may specify a hard-to-guess nonce matching the nonce attributes of
 * inline HTML blocks.
 *
 * <p>
 * To ease writing nonce-based CSP headers, this class replaces the {@code {nonce}}
 * placeholder in the {@code policyDirectives} with a real nonce value read from a
 * {@link ServerWebExchange#getAttribute(String) request attribute}. A
 * {@link ContentSecurityPolicyNonceGeneratingWebFilter} can be configured to generate a
 * unique secure random {@code Mono<ContentSecurityPolicyNonce>} attribute for each
 * request.
 *
 * <p>
 * For example, if the configured {@code policyDirectives} is {@code script-src 'self'
 * 'nonce-{nonce}'}, and a {@link ContentSecurityPolicyNonceGeneratingWebFilter} has set a
 * {@link ContentSecurityPolicyNonce} of {@code "Nc3n83cnSAd3wc3Sasdfn9"}, then the
 * written HTTP header value would be
 * {@code script-src 'self' 'nonce-Nc3n83cnSAd3wc3Sasdfn9'}.
 *
 * @author Vedran Pavic
 * @author Ziqin Wang
 * @since 5.1
 * @see ContentSecurityPolicyNonceGeneratingWebFilter
 */
public final class ContentSecurityPolicyServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	public static final String CONTENT_SECURITY_POLICY = "Content-Security-Policy";

	public static final String CONTENT_SECURITY_POLICY_REPORT_ONLY = "Content-Security-Policy-Report-Only";

	private static final String NONCE_PLACEHOLDER = "{nonce}";

	private ServerWebExchangeMatcher exchangeMatcher = ServerWebExchangeMatchers.anyExchange();

	private @Nullable String policyDirectives;

	private boolean reportOnly;

	private boolean isNonceBased;

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return Mono.justOrEmpty(this.policyDirectives)
			.filterWhen((ignored) -> this.exchangeMatcher.matches(exchange)
				.map(ServerWebExchangeMatcher.MatchResult::isMatch))
			.flatMap((csp) -> {
				String headerName = resolveHeader(this.reportOnly);
				HttpHeaders headers = exchange.getResponse().getHeaders();

				if (headers.containsHeader(headerName)) {
					return Mono.empty();
				}

				if (!this.isNonceBased) {
					headers.put(headerName, List.of(csp));
					return Mono.empty();
				}

				Mono<? extends ContentSecurityPolicyNonce> deferredNonce = exchange
					.getAttribute(ContentSecurityPolicyNonce.class.getName());
				if (deferredNonce == null) {
					return Mono.error(new IllegalStateException(
							"Failed to replace {nonce} placeholders since no nonce found as an exchange attribute "
									+ ContentSecurityPolicyNonce.class.getName()));
				}
				return deferredNonce.doOnNext((ContentSecurityPolicyNonce nonce) -> {
					String cspWithNonce = csp.replace(NONCE_PLACEHOLDER, nonce.getNonce());
					headers.put(headerName, List.of(cspWithNonce));
				}).then();
			});
	}

	/**
	 * Sets the {@link ServerWebExchangeMatcher} which determines whether CSP should be
	 * written. The default is to write CSP unconditionally.
	 * @param exchangeMatcher the {@link ServerWebExchangeMatcher} to use
	 * @throws IllegalArgumentException if {@code exchangeMatcher} is null
	 * @since 7.2
	 */
	public void setExchangeMatcher(ServerWebExchangeMatcher exchangeMatcher) {
		Assert.notNull(exchangeMatcher, "exchangeMatcher cannot be null");
		this.exchangeMatcher = exchangeMatcher;
	}

	/**
	 * Set the policy directive(s) to be used in the response header. The
	 * {@code policyDirectives} may contain {@code {nonce}} as placeholders to be
	 * replaced.
	 * @param policyDirectives the policy directive(s)
	 * @throws IllegalArgumentException if policyDirectives is {@code null} or empty
	 */
	public void setPolicyDirectives(String policyDirectives) {
		Assert.hasLength(policyDirectives, "policyDirectives must not be null or empty");
		this.policyDirectives = policyDirectives;
		this.isNonceBased = policyDirectives.contains(NONCE_PLACEHOLDER);
	}

	/**
	 * Set whether to include the {@code Content-Security-Policy-Report-Only} header in
	 * the response. Otherwise, defaults to the {@code Content-Security-Policy} header.
	 * @param reportOnly whether to only report policy violations
	 */
	public void setReportOnly(boolean reportOnly) {
		this.reportOnly = reportOnly;
	}

	private static String resolveHeader(boolean reportOnly) {
		return reportOnly ? CONTENT_SECURITY_POLICY_REPORT_ONLY : CONTENT_SECURITY_POLICY;
	}

}
