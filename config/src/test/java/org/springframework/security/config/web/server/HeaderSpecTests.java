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

package org.springframework.security.config.web.server;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.header.ContentSecurityPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentTypeOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.FeaturePolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy;
import org.springframework.security.web.server.header.StrictTransportSecurityServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Tests for {@link ServerHttpSecurity.HeaderSpec}.
 *
 * @author Rob Winch
 * @author Vedran Pavic
 * @author Ankur Pathak
 * @since 5.0
 */
public class HeaderSpecTests {

	private static final String CUSTOM_HEADER = "CUSTOM-HEADER";

	private static final String CUSTOM_VALUE = "CUSTOM-VALUE";

	private ServerHttpSecurity http = ServerHttpSecurity.http();

	private HttpHeaders expectedHeaders = new HttpHeaders();

	private Set<String> headerNamesNotPresent = new HashSet<>();

	@Before
	public void setup() {
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY,
				"max-age=31536000 ; includeSubDomains");
		this.expectedHeaders.add(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate");
		this.expectedHeaders.add(HttpHeaders.PRAGMA, "no-cache");
		this.expectedHeaders.add(HttpHeaders.EXPIRES, "0");
		this.expectedHeaders.add(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS, "nosniff");
		this.expectedHeaders.add(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, "DENY");
		this.expectedHeaders.add(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "1 ; mode=block");
	}

	@Test
	public void headersWhenDisableThenNoSecurityHeaders() {
		new HashSet<>(this.expectedHeaders.keySet()).forEach(this::expectHeaderNamesNotPresent);

		this.http.headers().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenDisableInLambdaThenNoSecurityHeaders() {
		new HashSet<>(this.expectedHeaders.keySet()).forEach(this::expectHeaderNamesNotPresent);

		this.http.headers(headers -> headers.disable());

		assertHeaders();
	}

	@Test
	public void headersWhenDisableAndInvokedExplicitlyThenDefautsUsed() {
		this.http.headers().disable().headers();

		assertHeaders();
	}

	@Test
	public void headersWhenDefaultsThenAllDefaultsWritten() {
		this.http.headers();

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
		this.http.headers().cache().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenCacheDisableInLambdaThenCacheNotWritten() {
		expectHeaderNamesNotPresent(HttpHeaders.CACHE_CONTROL, HttpHeaders.PRAGMA, HttpHeaders.EXPIRES);
		this.http.headers(headers -> headers.cache(cache -> cache.disable()));

		assertHeaders();
	}

	@Test
	public void headersWhenContentOptionsDisableThenContentTypeOptionsNotWritten() {
		expectHeaderNamesNotPresent(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS);
		this.http.headers().contentTypeOptions().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenContentOptionsDisableInLambdaThenContentTypeOptionsNotWritten() {
		expectHeaderNamesNotPresent(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS);
		this.http.headers(headers -> headers.contentTypeOptions(contentTypeOptions -> contentTypeOptions.disable()));

		assertHeaders();
	}

	@Test
	public void headersWhenHstsDisableThenHstsNotWritten() {
		expectHeaderNamesNotPresent(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.http.headers().hsts().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenHstsDisableInLambdaThenHstsNotWritten() {
		expectHeaderNamesNotPresent(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.http.headers(headers -> headers.hsts(hsts -> hsts.disable()));

		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomThenCustomHstsWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY,
				"max-age=60");
		this.http.headers().hsts().maxAge(Duration.ofSeconds(60)).includeSubdomains(false);

		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomInLambdaThenCustomHstsWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY,
				"max-age=60");
		this.http
				.headers(headers -> headers.hsts(hsts -> hsts.maxAge(Duration.ofSeconds(60)).includeSubdomains(false)));

		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomWithPreloadThenCustomHstsWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY,
				"max-age=60 ; includeSubDomains ; preload");
		this.http.headers().hsts().maxAge(Duration.ofSeconds(60)).preload(true);

		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomWithPreloadInLambdaThenCustomHstsWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY,
				"max-age=60 ; includeSubDomains ; preload");
		this.http.headers(headers -> headers.hsts(hsts -> hsts.maxAge(Duration.ofSeconds(60)).preload(true)));

		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsDisableThenFrameOptionsNotWritten() {
		expectHeaderNamesNotPresent(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS);
		this.http.headers().frameOptions().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsDisableInLambdaThenFrameOptionsNotWritten() {
		expectHeaderNamesNotPresent(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS);
		this.http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));

		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsModeThenFrameOptionsCustomMode() {
		this.expectedHeaders.set(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, "SAMEORIGIN");
		this.http.headers().frameOptions().mode(XFrameOptionsServerHttpHeadersWriter.Mode.SAMEORIGIN);

		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsModeInLambdaThenFrameOptionsCustomMode() {
		this.expectedHeaders.set(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, "SAMEORIGIN");
		this.http.headers(headers -> headers
				.frameOptions(frameOptions -> frameOptions.mode(XFrameOptionsServerHttpHeadersWriter.Mode.SAMEORIGIN)));

		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionDisableThenXssProtectionNotWritten() {
		expectHeaderNamesNotPresent("X-Xss-Protection");
		this.http.headers().xssProtection().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionDisableInLambdaThenXssProtectionNotWritten() {
		expectHeaderNamesNotPresent("X-Xss-Protection");
		this.http.headers(headers -> headers.xssProtection(xssProtection -> xssProtection.disable()));

		assertHeaders();
	}

	@Test
	public void headersWhenFeaturePolicyEnabledThenFeaturePolicyWritten() {
		String policyDirectives = "Feature-Policy";
		this.expectedHeaders.add(FeaturePolicyServerHttpHeadersWriter.FEATURE_POLICY, policyDirectives);

		this.http.headers().featurePolicy(policyDirectives);

		assertHeaders();
	}

	@Test
	public void headersWhenContentSecurityPolicyEnabledThenFeaturePolicyWritten() {
		String policyDirectives = "default-src 'self'";
		this.expectedHeaders.add(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY,
				policyDirectives);

		this.http.headers().contentSecurityPolicy(policyDirectives);

		assertHeaders();
	}

	@Test
	public void headersWhenContentSecurityPolicyEnabledWithDefaultsInLambdaThenDefaultPolicyWritten() {
		String expectedPolicyDirectives = "default-src 'self'";
		this.expectedHeaders.add(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY,
				expectedPolicyDirectives);

		this.http.headers(headers -> headers.contentSecurityPolicy(withDefaults()));

		assertHeaders();
	}

	@Test
	public void headersWhenContentSecurityPolicyEnabledInLambdaThenContentSecurityPolicyWritten() {
		String policyDirectives = "default-src 'self' *.trusted.com";
		this.expectedHeaders.add(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY,
				policyDirectives);

		this.http.headers(headers -> headers.contentSecurityPolicy(
				contentSecurityPolicy -> contentSecurityPolicy.policyDirectives(policyDirectives)));

		assertHeaders();
	}

	@Test
	public void headersWhenReferrerPolicyEnabledThenFeaturePolicyWritten() {
		this.expectedHeaders.add(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				ReferrerPolicy.NO_REFERRER.getPolicy());
		this.http.headers().referrerPolicy();

		assertHeaders();
	}

	@Test
	public void headersWhenReferrerPolicyEnabledInLambdaThenReferrerPolicyWritten() {
		this.expectedHeaders.add(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				ReferrerPolicy.NO_REFERRER.getPolicy());
		this.http.headers(headers -> headers.referrerPolicy(withDefaults()));

		assertHeaders();
	}

	@Test
	public void headersWhenReferrerPolicyCustomEnabledThenFeaturePolicyCustomWritten() {
		this.expectedHeaders.add(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE.getPolicy());
		this.http.headers().referrerPolicy(ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE);

		assertHeaders();
	}

	@Test
	public void headersWhenReferrerPolicyCustomEnabledInLambdaThenCustomReferrerPolicyWritten() {
		this.expectedHeaders.add(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE.getPolicy());
		this.http.headers(headers -> headers
				.referrerPolicy(referrerPolicy -> referrerPolicy.policy(ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE)));

		assertHeaders();
	}

	@Test
	public void headersWhenCustomHeadersWriter() {
		this.expectedHeaders.add(CUSTOM_HEADER, CUSTOM_VALUE);
		this.http.headers(headers -> headers.writer(exchange -> {
			return Mono.just(exchange).doOnNext(it -> {
				it.getResponse().getHeaders().add(CUSTOM_HEADER, CUSTOM_VALUE);
			}).then();

		}));

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
		FluxExchangeResult<String> response = client.get().uri("https://example.com/").exchange()
				.returnResult(String.class);

		Map<String, List<String>> responseHeaders = response.getResponseHeaders();

		if (!this.expectedHeaders.isEmpty()) {
			assertThat(responseHeaders).describedAs(response.toString()).containsAllEntriesOf(this.expectedHeaders);
		}
		if (!this.headerNamesNotPresent.isEmpty()) {
			assertThat(responseHeaders.keySet()).doesNotContainAnyElementsOf(this.headerNamesNotPresent);
		}
	}

	private WebTestClient buildClient() {
		return WebTestClientBuilder.bindToWebFilters(this.http.build()).build();
	}

}
