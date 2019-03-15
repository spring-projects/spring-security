/*
 * Copyright 2002-2018 the original author or authors.
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

/**
 * Tests for {@link ServerHttpSecurity.HeaderSpec}.
 *
 * @author Rob Winch
 * @author Vedran Pavic
 * @since 5.0
 */
public class HeaderSpecTests {

	private ServerHttpSecurity.HeaderSpec headers = ServerHttpSecurity.http().headers();

	private HttpHeaders expectedHeaders = new HttpHeaders();

	private Set<String> headerNamesNotPresent = new HashSet<>();

	@Before
	public void setup() {
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains");
		this.expectedHeaders.add(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate");
		this.expectedHeaders.add(HttpHeaders.PRAGMA, "no-cache");
		this.expectedHeaders.add(HttpHeaders.EXPIRES, "0");
		this.expectedHeaders
			.add(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS, "nosniff");
		this.expectedHeaders.add(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, "DENY");
		this.expectedHeaders
			.add(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, "1 ; mode=block");
	}

	@Test
	public void headersWhenDisableThenNoSecurityHeaders() {
		new HashSet<>(this.expectedHeaders.keySet()).forEach(this::expectHeaderNamesNotPresent);

		this.headers.disable();

		assertHeaders();
	}

	@Test
	public void headersWhenDisableAndInvokedExplicitlyThenDefautsUsed() {
		this.headers.disable()
			.headers();

		assertHeaders();
	}

	@Test
	public void headersWhenDefaultsThenAllDefaultsWritten() {
		assertHeaders();
	}

	@Test
	public void headersWhenCacheDisableThenCacheNotWritten() {
		expectHeaderNamesNotPresent(HttpHeaders.CACHE_CONTROL, HttpHeaders.PRAGMA, HttpHeaders.EXPIRES);
		this.headers.cache().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenContentOptionsDisableThenContentTypeOptionsNotWritten() {
		expectHeaderNamesNotPresent(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS);
		this.headers.contentTypeOptions().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenHstsDisableThenHstsNotWritten() {
		expectHeaderNamesNotPresent(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.headers.hsts().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomThenCustomHstsWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.expectedHeaders.add(StrictTransportSecurityServerHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=60");
		this.headers.hsts()
					.maxAge(Duration.ofSeconds(60))
					.includeSubdomains(false);

		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsDisableThenFrameOptionsNotWritten() {
		expectHeaderNamesNotPresent(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS);
		this.headers.frameOptions().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsModeThenFrameOptionsCustomMode() {
		this.expectedHeaders.set(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, "SAMEORIGIN");
		this.headers
				.frameOptions()
					.mode(XFrameOptionsServerHttpHeadersWriter.Mode.SAMEORIGIN);

		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionDisableThenXssProtectionNotWritten() {
		expectHeaderNamesNotPresent("X-Xss-Protection");
		this.headers.xssProtection().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenFeaturePolicyEnabledThenFeaturePolicyWritten() {
		String policyDirectives = "Feature-Policy";
		this.expectedHeaders.add(FeaturePolicyServerHttpHeadersWriter.FEATURE_POLICY,
				policyDirectives);

		this.headers.featurePolicy(policyDirectives);

		assertHeaders();
	}

	@Test
	public void headersWhenContentSecurityPolicyEnabledThenFeaturePolicyWritten() {
		String policyDirectives = "default-src 'self'";
		this.expectedHeaders.add(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY,
				policyDirectives);

		this.headers.contentSecurityPolicy(policyDirectives);

		assertHeaders();
	}

	@Test
	public void headersWhenReferrerPolicyEnabledThenFeaturePolicyWritten() {
		this.expectedHeaders.add(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				ReferrerPolicy.NO_REFERRER.getPolicy());
		this.headers.referrerPolicy();

		assertHeaders();
	}

	@Test
	public void headersWhenReferrerPolicyCustomEnabledThenFeaturePolicyCustomWritten() {
		this.expectedHeaders.add(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE.getPolicy());
		this.headers.referrerPolicy(ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE);

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

		Map<String, List<String>> responseHeaders = response.getResponseHeaders();

		if (!this.expectedHeaders.isEmpty()) {
			assertThat(responseHeaders).describedAs(response.toString())
					.containsAllEntriesOf(this.expectedHeaders);
		}
		if (!this.headerNamesNotPresent.isEmpty()) {
			assertThat(responseHeaders.keySet()).doesNotContainAnyElementsOf(this.headerNamesNotPresent);
		}
	}

	private WebTestClient buildClient() {
		return WebTestClientBuilder.bindToWebFilters(this.headers.and().build()).build();
	}
}
