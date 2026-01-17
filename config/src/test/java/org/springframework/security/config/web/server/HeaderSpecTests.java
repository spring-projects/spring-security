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

package org.springframework.security.config.web.server;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.header.ContentSecurityPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CrossOriginEmbedderPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CrossOriginOpenerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.CrossOriginResourcePolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.FeaturePolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy;
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.assertj.WebTestClientResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.ResponseBody;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Tests for {@link ServerHttpSecurity.HeaderSpec}.
 *
 * @author Rob Winch
 * @author Vedran Pavic
 * @author Ankur Pathak
 * @author Marcus Da Coregio
 * @author Ziqin Wang
 * @since 5.0
 */
public class HeaderSpecTests {

	private static final String CUSTOM_HEADER = "CUSTOM-HEADER";

	private static final String CUSTOM_VALUE = "CUSTOM-VALUE";

	private ServerHttpSecurity http = ServerHttpSecurity.http();

	private HttpHeaders expectedHeaders = new HttpHeaders();

	private Set<String> headerNamesNotPresent = new HashSet<>();

	@BeforeEach
	public void setup() {
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY,
				"max-age=31536000 ; includeSubDomains");
		this.expectedHeaders.add(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate");
		this.expectedHeaders.add(HttpHeaders.PRAGMA, "no-cache");
		this.expectedHeaders.add(HttpHeaders.EXPIRES, "0");
		this.expectedHeaders.add(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS, "nosniff");
		this.expectedHeaders.add(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, "DENY");
		this.expectedHeaders.add(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "0");
	}

	@Test
	public void headersWhenDisableThenNoSecurityHeaders() {
		new HashSet<>(this.expectedHeaders.headerNames()).forEach(this::expectHeaderNamesNotPresent);
		this.http.headers((headers) -> headers.disable());
		assertHeaders();
	}

	@Test
	public void headersWhenDisableInLambdaThenNoSecurityHeaders() {
		new HashSet<>(this.expectedHeaders.headerNames()).forEach(this::expectHeaderNamesNotPresent);
		this.http.headers((headers) -> headers.disable());
		assertHeaders();
	}

	@Test
	public void headersWhenDisableAndInvokedExplicitlyThenDefautsUsed() {
		this.http.headers((headers) -> headers.disable().headers(Customizer.withDefaults()));
		assertHeaders();
	}

	@Test
	public void headersWhenDefaultsThenAllDefaultsWritten() {
		this.http.headers(withDefaults());
		assertHeaders();
	}

	@Test
	public void headersWhenDefaultsInLambdaThenAllDefaultsWritten() {
		this.http.headers(withDefaults());
		assertHeaders();
	}

	@Test
	public void headersWhenCacheDisableThenCacheNotWritten() {
		expectHeaderNamesNotPresent(HttpHeaders.CACHE_CONTROL, HttpHeaders.PRAGMA, HttpHeaders.EXPIRES);
		this.http.headers((headers) -> headers.cache((cache) -> cache.disable()));
		assertHeaders();
	}

	@Test
	public void headersWhenCacheDisableInLambdaThenCacheNotWritten() {
		expectHeaderNamesNotPresent(HttpHeaders.CACHE_CONTROL, HttpHeaders.PRAGMA, HttpHeaders.EXPIRES);
		// @formatter:off
		this.http.headers((headers) -> headers
				.cache((cache) -> cache.disable())
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenContentOptionsDisableThenContentTypeOptionsNotWritten() {
		expectHeaderNamesNotPresent(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS);
		this.http.headers((headers) -> headers.contentTypeOptions((options) -> options.disable()));
		assertHeaders();
	}

	@Test
	public void headersWhenContentOptionsDisableInLambdaThenContentTypeOptionsNotWritten() {
		expectHeaderNamesNotPresent(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS);
		// @formatter:off
		this.http
				.headers((headers) -> headers
						.contentTypeOptions((contentTypeOptions) -> contentTypeOptions.disable()
				));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenHstsDisableThenHstsNotWritten() {
		expectHeaderNamesNotPresent(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.http.headers((headers) -> headers.hsts((hsts) -> hsts.disable()));
		assertHeaders();
	}

	@Test
	public void headersWhenHstsDisableInLambdaThenHstsNotWritten() {
		expectHeaderNamesNotPresent(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		// @formatter:off
		this.http.headers((headers) -> headers
				.hsts((hsts) -> hsts.disable())
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomThenCustomHstsWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY,
				"max-age=60");
		// @formatter:off
		this.http.headers((headers) -> headers
			.hsts((hsts) -> hsts
				.maxAge(Duration.ofSeconds(60))
				.includeSubdomains(false)));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomInLambdaThenCustomHstsWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY,
				"max-age=60");
		// @formatter:off
		this.http.headers(
				(headers) -> headers
						.hsts((hsts) -> hsts
								.maxAge(Duration.ofSeconds(60))
								.includeSubdomains(false)
						)
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomWithPreloadThenCustomHstsWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY,
				"max-age=60 ; includeSubDomains ; preload");
		// @formatter:off
		this.http.headers((headers) -> headers
			.hsts((hsts) -> hsts
				.maxAge(Duration.ofSeconds(60))
				.preload(true)));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomWithPreloadInLambdaThenCustomHstsWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY,
				"max-age=60 ; includeSubDomains ; preload");
		// @formatter:off
		this.http.headers((headers) -> headers
				.hsts((hsts) -> hsts
						.maxAge(Duration.ofSeconds(60))
						.preload(true)
				)
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsDisableThenFrameOptionsNotWritten() {
		expectHeaderNamesNotPresent(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS);
		// @formatter:off
		this.http.headers((headers) -> headers
			.frameOptions((options) -> options.disable()));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsDisableInLambdaThenFrameOptionsNotWritten() {
		expectHeaderNamesNotPresent(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS);
		// @formatter:off
		this.http.headers((headers) -> headers
				.frameOptions((frameOptions) -> frameOptions
						.disable()
				)
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsModeThenFrameOptionsCustomMode() {
		this.expectedHeaders.set(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, "SAMEORIGIN");
		// @formatter:off
		this.http.headers((headers) -> headers
			.frameOptions((frameOptions) -> frameOptions
				.mode(XFrameOptionsServerHttpHeadersWriter.Mode.SAMEORIGIN)));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsModeInLambdaThenFrameOptionsCustomMode() {
		this.expectedHeaders.set(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, "SAMEORIGIN");
		// @formatter:off
		this.http.headers((headers) -> headers
				.frameOptions((frameOptions) -> frameOptions
						.mode(XFrameOptionsServerHttpHeadersWriter.Mode.SAMEORIGIN)
				)
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionDisableThenXssProtectionNotWritten() {
		expectHeaderNamesNotPresent("X-Xss-Protection");
		// @formatter:off
		this.http.headers((headers) -> headers
			.xssProtection((xss) -> xss.disable()));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionDisableInLambdaThenXssProtectionNotWritten() {
		expectHeaderNamesNotPresent("X-Xss-Protection");
		// @formatter:off
		this.http.headers((headers) -> headers
				.xssProtection((xssProtection) -> xssProtection
						.disable()
				)
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionValueDisabledThenXssProtectionWritten() {
		this.expectedHeaders.set(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "0");
		// @formatter:off
		this.http.headers((headers) -> headers
			.xssProtection((xss) -> xss
				.headerValue(XXssProtectionServerHttpHeadersWriter.HeaderValue.DISABLED)));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionValueEnabledThenXssProtectionWritten() {
		this.expectedHeaders.set(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "1");
		// @formatter:off
		this.http.headers((headers) -> headers
			.xssProtection((xss) -> xss
				.headerValue(XXssProtectionServerHttpHeadersWriter.HeaderValue.ENABLED)));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionValueEnabledModeBlockThenXssProtectionWritten() {
		this.expectedHeaders.set(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "1; mode=block");
		// @formatter:off
		this.http.headers((headers) -> headers
			.xssProtection((xss) -> xss
				.headerValue(XXssProtectionServerHttpHeadersWriter.HeaderValue.ENABLED_MODE_BLOCK)));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionValueDisabledInLambdaThenXssProtectionWritten() {
		this.expectedHeaders.set(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "0");
		// @formatter:off
		this.http.headers((headers) -> headers
			.xssProtection((xssProtection) -> xssProtection.headerValue(XXssProtectionServerHttpHeadersWriter.HeaderValue.DISABLED)
			));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenFeaturePolicyEnabledThenFeaturePolicyWritten() {
		String policyDirectives = "Feature-Policy";
		this.expectedHeaders.add(FeaturePolicyServerHttpHeadersWriter.FEATURE_POLICY, policyDirectives);
		// @formatter:off
		this.http.headers((headers) -> headers
			.featurePolicy(policyDirectives));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenContentSecurityPolicyEnabledThenFeaturePolicyWritten() {
		String policyDirectives = "default-src 'self'";
		this.expectedHeaders.add(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY,
				policyDirectives);
		// @formatter:off
		this.http.headers((headers) -> headers
			.contentSecurityPolicy((csp) -> csp.policyDirectives(policyDirectives)));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenContentSecurityPolicyEnabledWithDefaultsInLambdaThenDefaultPolicyWritten() {
		String expectedPolicyDirectives = "default-src 'self'";
		this.expectedHeaders.add(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY,
				expectedPolicyDirectives);
		// @formatter:off
		this.http.headers((headers) -> headers
				.contentSecurityPolicy(withDefaults())
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenContentSecurityPolicyEnabledInLambdaThenContentSecurityPolicyWritten() {
		String policyDirectives = "default-src 'self' *.trusted.com";
		this.expectedHeaders.add(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY,
				policyDirectives);
		// @formatter:off
		this.http.headers((headers) -> headers
				.contentSecurityPolicy((csp) -> csp
						.policyDirectives(policyDirectives)
				)
		);
		// @formatter:on
		assertHeaders();
	}

	/** @since 7.1 */
	@Test
	public void headersWhenContentSecurityPolicyEnabledWithDefaultNonceThenHeaderMatchesContent() {
		String headerName = ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY;
		Pattern regex = Pattern.compile("^script-src 'self' 'nonce-([A-Za-z0-9+/]{22,}={0,2})'$");

		// @formatter:off
		this.http.headers((headers) -> headers
			.contentSecurityPolicy((csp) -> csp
				.policyDirectives("script-src 'self' 'nonce-{nonce}'")));
		// @formatter:on
		WebTestClient client = WebTestClientBuilder
			.bindToControllerAndWebFilters(ReactiveTestCspNonceController.class, this.http.build())
			.build();

		WebTestClient.ResponseSpec spec = client.get().uri("https://example.com/").exchange();
		WebTestClientResponse response = WebTestClientResponse.from(spec);

		assertThat(response).hasContentTypeCompatibleWith(MediaType.TEXT_HTML);
		assertThat(response).headers().hasHeaderSatisfying(headerName, (cspList) -> {
			assertThat(cspList).singleElement().asString().matchesSatisfying(regex, (matcher) -> {
				String nonce = matcher.group(1);
				assertThat(nonce).isNotNull();
				assertThat(response).bodyText().contains("nonce=\"" + nonce + "\"");
			});
		});
	}

	/** @since 7.1 */
	@Test
	public void headersWhenContentSecurityPolicyEnabledWithCustomNonceThenHeaderMatchesContent() {
		String headerName = ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY;
		Pattern regex = Pattern.compile("^script-src 'self' 'nonce-([A-Za-z0-9+/]{22,}={0,2})'$");

		// @formatter:off
		this.http.headers((headers) -> headers
			.contentSecurityPolicy((csp) -> csp
				.nonceAttributeName("CUSTOM_NONCE")
				.policyDirectives("script-src 'self' 'nonce-{nonce}'")));
		// @formatter:on
		WebTestClient client = WebTestClientBuilder
			.bindToControllerAndWebFilters(ReactiveTestCspNonceController.class, this.http.build())
			.build();

		WebTestClient.ResponseSpec spec = client.get().uri("https://example.com/custom").exchange();
		WebTestClientResponse response = WebTestClientResponse.from(spec);

		assertThat(response).hasContentTypeCompatibleWith(MediaType.TEXT_HTML);
		assertThat(response).headers().hasHeaderSatisfying(headerName, (cspList) -> {
			assertThat(cspList).singleElement().asString().matchesSatisfying(regex, (matcher) -> {
				String nonce = matcher.group(1);
				assertThat(nonce).isNotNull();
				assertThat(response).bodyText().contains("nonce=\"" + nonce + "\"");
			});
		});
	}

	/** @since 7.1 */
	@Test
	public void headersWhenContentSecurityPolicyEnabledWithMatcherThenHeaderInResponseIfMatched() {
		String headerName = ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY;
		String policyDirectives = "default-src 'self'";
		// @formatter:off
		this.http.headers((headers) -> headers
			.contentSecurityPolicy((csp) -> csp
				.requireCspMatcher((exchange) ->
					(MediaType.TEXT_HTML.isPresentIn(exchange.getRequest().getHeaders().getAccept()) ?
						ServerWebExchangeMatcher.MatchResult.match() :
						ServerWebExchangeMatcher.MatchResult.notMatch()))
				.policyDirectives(policyDirectives)));
		// @formatter:on
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.http.build()).build();
		// @formatter:off
		client.get()
			.uri("https://example.com/")
			.accept(MediaType.TEXT_HTML)
			.exchange()
			.expectHeader().valueEquals(headerName, policyDirectives);
		client.get()
			.uri("https://example.com/")
			.accept(MediaType.TEXT_PLAIN)
			.exchange()
			.expectHeader().doesNotExist(headerName);
		// @formatter:on
	}

	/** @since 7.1 */
	@Test
	public void headersWhenContentSecurityPolicyEnabledWithPathMatchersThenHeaderInResponseIfMatched() {
		String headerName = ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY;
		String policyDirectives = "default-src 'self'";
		// @formatter:off
		this.http.headers((headers) -> headers
			.contentSecurityPolicy((csp) -> csp
				.requireCspMatchers("/foo/**", "/bar/**")
				.policyDirectives(policyDirectives)));
		// @formatter:on
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.http.build()).build();
		// @formatter:off
		client.get()
			.uri("https://example.com/foo/bar")
			.exchange()
			.expectHeader().valueEquals(headerName, policyDirectives);
		client.get()
			.uri("https://example.com/bar/foo")
			.exchange()
			.expectHeader().valueEquals(headerName, policyDirectives);
		client.get()
			.uri("https://example.com/foobar")
			.exchange()
			.expectHeader().doesNotExist(headerName);
		// @formatter:on
	}

	/** @since 7.1 */
	@Test
	public void headersWhenContentSecurityPolicyWithOverriddenMatchersThenFailToConfigure() {
		// @formatter:off
		assertThatIllegalStateException()
			.isThrownBy(() -> this.http
				.headers((headers) -> headers
					.contentSecurityPolicy((csp) -> csp
						.requireCspMatcher(ServerWebExchangeMatchers.anyExchange())
						.requireCspMatchers("/**")
						.policyDirectives("default-src 'self'"))))
			.withMessage("RequireCspMatcher(s) is already configured");
		// @formatter:on
	}

	@Test
	public void headersWhenReferrerPolicyEnabledThenFeaturePolicyWritten() {
		this.expectedHeaders.add(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				ReferrerPolicy.NO_REFERRER.getPolicy());
		// @formatter:off
		this.http.headers((headers) -> headers
			.referrerPolicy(Customizer.withDefaults()));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenReferrerPolicyEnabledInLambdaThenReferrerPolicyWritten() {
		this.expectedHeaders.add(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				ReferrerPolicy.NO_REFERRER.getPolicy());
		// @formatter:off
		this.http.headers((headers) -> headers
				.referrerPolicy(withDefaults()
				)
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenReferrerPolicyCustomEnabledThenFeaturePolicyCustomWritten() {
		this.expectedHeaders.add(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE.getPolicy());
		// @formatter:off
		this.http.headers((headers) -> headers
			.referrerPolicy((referrer) -> referrer.policy(ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE)));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenReferrerPolicyCustomEnabledInLambdaThenCustomReferrerPolicyWritten() {
		this.expectedHeaders.add(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE.getPolicy());
		// @formatter:off
		this.http.headers((headers) -> headers
				.referrerPolicy((referrerPolicy) -> referrerPolicy
						.policy(ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE)
				)
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenCustomHeadersWriter() {
		this.expectedHeaders.add(CUSTOM_HEADER, CUSTOM_VALUE);
		// @formatter:off
		this.http.headers((headers) -> headers
				.writer((exchange) -> Mono.just(exchange)
					.doOnNext((it) -> it.getResponse().getHeaders().add(CUSTOM_HEADER, CUSTOM_VALUE))
					.then()
				)
		);
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenCrossOriginPoliciesCustomEnabledThenCustomCrossOriginPoliciesWritten() {
		this.expectedHeaders.add(CrossOriginOpenerPolicyServerHttpHeadersWriter.OPENER_POLICY,
				CrossOriginOpenerPolicyServerHttpHeadersWriter.CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS
					.getPolicy());
		this.expectedHeaders.add(CrossOriginEmbedderPolicyServerHttpHeadersWriter.EMBEDDER_POLICY,
				CrossOriginEmbedderPolicyServerHttpHeadersWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP.getPolicy());
		this.expectedHeaders.add(CrossOriginResourcePolicyServerHttpHeadersWriter.RESOURCE_POLICY,
				CrossOriginResourcePolicyServerHttpHeadersWriter.CrossOriginResourcePolicy.SAME_ORIGIN.getPolicy());
		// @formatter:off
		this.http.headers((headers) -> headers
			.crossOriginOpenerPolicy((opener) -> opener
				.policy(CrossOriginOpenerPolicyServerHttpHeadersWriter.CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS))
			.crossOriginEmbedderPolicy((embedder) -> embedder
				.policy(CrossOriginEmbedderPolicyServerHttpHeadersWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP))
			.crossOriginResourcePolicy((resource) -> resource
				.policy(CrossOriginResourcePolicyServerHttpHeadersWriter.CrossOriginResourcePolicy.SAME_ORIGIN)));
		// @formatter:on
		assertHeaders();
	}

	@Test
	public void headersWhenCrossOriginPoliciesCustomEnabledInLambdaThenCustomCrossOriginPoliciesWritten() {
		this.expectedHeaders.add(CrossOriginOpenerPolicyServerHttpHeadersWriter.OPENER_POLICY,
				CrossOriginOpenerPolicyServerHttpHeadersWriter.CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS
					.getPolicy());
		this.expectedHeaders.add(CrossOriginEmbedderPolicyServerHttpHeadersWriter.EMBEDDER_POLICY,
				CrossOriginEmbedderPolicyServerHttpHeadersWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP.getPolicy());
		this.expectedHeaders.add(CrossOriginResourcePolicyServerHttpHeadersWriter.RESOURCE_POLICY,
				CrossOriginResourcePolicyServerHttpHeadersWriter.CrossOriginResourcePolicy.SAME_ORIGIN.getPolicy());
		// @formatter:off
		this.http.headers((headers) -> headers
			.crossOriginOpenerPolicy((policy) -> policy
					.policy(CrossOriginOpenerPolicyServerHttpHeadersWriter.CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS)
			)
			.crossOriginEmbedderPolicy((policy) -> policy
					.policy(CrossOriginEmbedderPolicyServerHttpHeadersWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP)
			)
			.crossOriginResourcePolicy((policy) -> policy
					.policy(CrossOriginResourcePolicyServerHttpHeadersWriter.CrossOriginResourcePolicy.SAME_ORIGIN)
			));
		// @formatter:on
		assertHeaders();
	}

	private void expectHeaderNamesNotPresent(String... headerNames) {
		for (String headerName : headerNames) {
			this.expectedHeaders.remove(headerName);
			this.headerNamesNotPresent.add(headerName);
		}
	}

	private void assertHeaders() {
		WebTestClient client = buildClient();
		FluxExchangeResult<String> response = client.get()
			.uri("https://example.com/")
			.exchange()
			.returnResult(String.class);
		HttpHeaders responseHeaders = response.getResponseHeaders();
		if (!this.expectedHeaders.isEmpty()) {
			this.expectedHeaders.forEach(
					(headerName, headerValues) -> assertThat(responseHeaders.get(headerName)).isEqualTo(headerValues));
		}
		if (!this.headerNamesNotPresent.isEmpty()) {
			assertThat(responseHeaders.headerNames()).doesNotContainAnyElementsOf(this.headerNamesNotPresent);
		}
	}

	private WebTestClient buildClient() {
		return WebTestClientBuilder.bindToWebFilters(this.http.build()).build();
	}

	@Controller
	static class ReactiveTestCspNonceController {

		@GetMapping(produces = MediaType.TEXT_HTML_VALUE)
		@ResponseBody
		Mono<String> defaultAttribute(@RequestAttribute("_csp_nonce") String cspNonce) {
			return Mono.fromSupplier(() -> """
					<!DOCTYPE html>
					<html>
					<head><script nonce="%s"></script></head>
					<body>Default</body>
					</html>
					""".formatted(cspNonce));
		}

		@GetMapping(path = "/custom", produces = MediaType.TEXT_HTML_VALUE)
		@ResponseBody
		Mono<String> custom(@RequestAttribute("CUSTOM_NONCE") String cspNonce) {
			return Mono.fromSupplier(() -> """
					<!DOCTYPE html>
					<html>
					<head><script nonce="%s"></script></head>
					<body>Custom</body>
					</html>
					""".formatted(cspNonce));
		}

	}

}
