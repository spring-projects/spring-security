/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
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
		expectedHeaders.add(StrictTransportSecurityHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains");
		expectedHeaders.add(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate");
		expectedHeaders.add(HttpHeaders.PRAGMA, "no-cache");
		expectedHeaders.add(HttpHeaders.EXPIRES, "0");
		expectedHeaders.add(ContentTypeOptionsHttpHeadersWriter.X_CONTENT_OPTIONS, "nosniff");
		expectedHeaders.add(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS, "DENY");
		expectedHeaders.add(XXssProtectionHttpHeadersWriter.X_XSS_PROTECTION, "1 ; mode=block");
	}

	@Test
	public void headersWhenDefaultsThenAllDefaultsWritten() {
		assertHeaders();
	}

	@Test
	public void headersWhenCacheDisableThenCacheNotWritten() {
		expectedHeaders.remove(HttpHeaders.CACHE_CONTROL);
		expectedHeaders.remove(HttpHeaders.PRAGMA);
		expectedHeaders.remove(HttpHeaders.EXPIRES);
		headers.cache().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenContentOptionsDisableThenContentTypeOptionsNotWritten() {
		expectedHeaders.remove(ContentTypeOptionsHttpHeadersWriter.X_CONTENT_OPTIONS);
		headers.contentTypeOptions().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenHstsDisableThenHstsNotWritten() {
		expectedHeaders.remove(StrictTransportSecurityHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		headers.hsts().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenHstsCustomThenCustomHstsWritten() {
		expectedHeaders.remove(StrictTransportSecurityHttpHeadersWriter.STRICT_TRANSPORT_SECURITY);
		expectedHeaders.add(StrictTransportSecurityHttpHeadersWriter.STRICT_TRANSPORT_SECURITY, "max-age=60");
		headers.hsts().maxAge(Duration.ofSeconds(60));
		headers.hsts().includeSubdomains(false);

		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsDisableThenFrameOptionsNotWritten() {
		expectedHeaders.remove(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS);
		headers.frameOptions().disable();

		assertHeaders();
	}

	@Test
	public void headersWhenFrameOptionsModeThenFrameOptionsCustomMode() {
		expectedHeaders.remove(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS);
		expectedHeaders.add(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS, "SAMEORIGIN");
		headers.frameOptions().mode(XFrameOptionsHttpHeadersWriter.Mode.SAMEORIGIN);

		assertHeaders();
	}

	@Test
	public void headersWhenXssProtectionDisableThenXssProtectionNotWritten() {
		expectedHeaders.remove("X-Xss-Protection");
		headers.xssProtection().disable();

		assertHeaders();
	}

	private void assertHeaders() {
		WebTestClient client = buildClient();
		FluxExchangeResult<String> response = client.get()
			.uri("https://example.com/")
			.exchange()
			.returnResult(String.class);

		Map<String,List<String>> responseHeaders = response.getResponseHeaders();
		ignoredHeaderNames.stream().forEach(responseHeaders::remove);

		assertThat(responseHeaders).describedAs(response.toString()).isEqualTo(expectedHeaders);
	}

	private WebTestClient buildClient() {
		return WebTestClientBuilder.bindToWebFilters(headers.build()).build();
	}
}
