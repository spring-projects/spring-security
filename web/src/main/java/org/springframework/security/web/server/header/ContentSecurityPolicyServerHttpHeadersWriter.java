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
 * {@link ServerWebExchange#getAttribute(String) request attribute} named
 * {@code _csp_nonce} (or another configured attribute name). A
 * {@link org.springframework.security.web.server.header.NonceGeneratingWebFilter} can be
 * configured to generate a unique secure random {@code _csp_nonce} attribute for each
 * request.
 *
 * <p>
 * For example, if the configured {@code policyDirectives} is {@code script-src 'self'
 * 'nonce-{nonce}'}, and a
 * {@link org.springframework.security.web.server.header.NonceGeneratingWebFilter} has set
 * the {@code _csp_nonce} attribute to {@code "Nc3n83cnSAd3wc3Sasdfn9"}, then the written
 * HTTP header value would be {@code script-src 'self' 'nonce-Nc3n83cnSAd3wc3Sasdfn9'}.
 *
 * @author Vedran Pavic
 * @author Ziqin Wang
 * @since 5.1
 */
public final class ContentSecurityPolicyServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	public static final String CONTENT_SECURITY_POLICY = "Content-Security-Policy";

	public static final String CONTENT_SECURITY_POLICY_REPORT_ONLY = "Content-Security-Policy-Report-Only";

	public static final String DEFAULT_NONCE_ATTRIBUTE_NAME = "_csp_nonce";

	public static final String NONCE_PLACEHOLDER = "{nonce}";

	private @Nullable String policyDirectives;

	private boolean reportOnly;

	private String nonceAttributeName = DEFAULT_NONCE_ATTRIBUTE_NAME;

	private boolean isNonceBased;

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return Mono.justOrEmpty(this.policyDirectives).flatMap((csp) -> {
			String headerName = resolveHeader(this.reportOnly);
			HttpHeaders headers = exchange.getResponse().getHeaders();
			if (!headers.containsHeader(headerName)) {
				if (this.isNonceBased) {
					String nonce = exchange.getAttribute(this.nonceAttributeName);
					if (nonce == null) {
						return Mono.error(new IllegalStateException("Nonce is unset"));
					}
					csp = csp.replace(NONCE_PLACEHOLDER, nonce);
				}
				headers.put(headerName, List.of(csp));
			}
			return Mono.empty();
		});
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

	/**
	 * Sets the name of the {@link ServerWebExchange#getAttribute(String) exchange
	 * attribute} from which the nonce value is taken. Defaults to {@code _csp_nonce} if
	 * unset.
	 * @param nonceAttributeName the name of the nonce attribute
	 * @throws IllegalArgumentException if {@code nonceAttributeName} is {@code null} or
	 * empty
	 * @since 7.1
	 */
	public void setNonceAttributeName(String nonceAttributeName) {
		Assert.hasLength(nonceAttributeName, "nonceAttributeName cannot be null or empty");
		this.nonceAttributeName = nonceAttributeName;
	}

	/**
	 * Returns the name of the {@link ServerWebExchange#getAttribute(String) request
	 * attribute} from which the nonce value is taken. Defaults to {@code _csp_nonce} if
	 * unset.
	 * @return the name of the nonce attribute.
	 * @since 7.1
	 */
	public String getNonceAttributeName() {
		return this.nonceAttributeName;
	}

	/**
	 * Returns whether the content security policy is nonce-based. The CSP is considered
	 * nonce-based if the configured {@code policyDirectives} string contains a
	 * {@code {nonce}} placeholder.
	 * @return whether the content security policy is nonce-based
	 * @since 7.1
	 */
	public boolean isNonceBased() {
		return this.isNonceBased;
	}

	private static String resolveHeader(boolean reportOnly) {
		return reportOnly ? CONTENT_SECURITY_POLICY_REPORT_ONLY : CONTENT_SECURITY_POLICY;
	}

}
