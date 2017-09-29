/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.web.server;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.header.ContentTypeOptionsHttpHeadersWriter;
import org.springframework.security.web.server.header.StrictTransportSecurityHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsHttpHeadersWriter;
import org.springframework.security.web.server.header.XXssProtectionHttpHeadersWriter;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class HeaderBuilderTests {

	HttpSecurity.HeaderBuilder headers = HttpSecurity.http().headers();

	HttpHeaders expectedHeaders = new HttpHeaders();

	Set<String> ignoredHeaderNames = Collections.singleton(HttpHeaders.CONTENT_TYPE);

	@Before
	public void setup() {
		this.expectedHeaders.add(StrictTransportSecurityHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains");
		this.expectedHeaders.add(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate");
		this.expectedHeaders.add(HttpHeaders.PRAGMA, "no-cache");
		this.expectedHeaders.add(HttpHeaders.EXPIRES, "0");
		this.expectedHeaders
			.add(ContentTypeOptionsHttpHeadersWriter.X_CONTENT_OPTIONS, "nosniff");
		this.expectedHeaders.add(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS, "DENY");
		this.expectedHeaders
			.add(XXssProtectionHttpHeadersWriter.X_XSS_PROTECTION, "1 ; mode=block");
	}

	@Test
	public void headersWhenDefaultsThenAllDefaultsWritten() {
		assertHeaders();
	}

	@Test
	public void headersWhenCacheDisableThenCacheNotWritten() {
		this.expectedHeaders.remove(HttpHeaders.CACHE_CONTROL);
		this.expectedHeaders.remove(HttpHeaders.PRAGMA);
		this.expectedHeaders.remove(HttpHeaders.EXPIRES);
		this.headers.cache().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenContentOptionsDisableThenContentTypeOptionsNotWritten() {
		this.expectedHeaders.remove(ContentTypeOptionsHttpHeadersWriter.X_CONTENT_OPTIONS);
		this.headers.contentTypeOptions().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenHstsDisableThenHstsNotWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.headers.hsts().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomThenCustomHstsWritten() {
		this.expectedHeaders.remove(StrictTransportSecurityHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		this.expectedHeaders.add(StrictTransportSecurityHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=60");
		this.headers.hsts().maxAge(Duration.ofSeconds(60));
		this.headers.hsts().includeSubdomains(false);

		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsDisableThenFrameOptionsNotWritten() {
		this.expectedHeaders.remove(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS);
		this.headers.frameOptions().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsModeThenFrameOptionsCustomMode() {
		this.expectedHeaders.remove(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS);
		this.expectedHeaders
			.add(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS, "SAMEORIGIN");
		this.headers.frameOptions().mode(XFrameOptionsHttpHeadersWriter.Mode.SAMEORIGIN);

		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionDisableThenXssProtectionNotWritten() {
		this.expectedHeaders.remove("X-Xss-Protection");
		this.headers.xssProtection().disable();

		assertHeaders();
	}

	private void assertHeaders() {
		WebTestClient client = buildClient();
		FluxExchangeResult<String> response = client.get()
			.uri("https://example.com/")
			.exchange()
			.returnResult(String.class);

		Map<String,List<String>> responseHeaders = response.getResponseHeaders();
		this.ignoredHeaderNames.stream().forEach(responseHeaders::remove);

		assertThat(responseHeaders).describedAs(response.toString()).isEqualTo(
			this.expectedHeaders);
	}

	private WebTestClient buildClient() {
		return WebTestClientBuilder.bindToWebFilters(this.headers.and().build()).build();
	}
}
