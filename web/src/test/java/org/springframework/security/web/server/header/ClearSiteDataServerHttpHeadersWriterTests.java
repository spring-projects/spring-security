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
package org.springframework.security.web.server.header;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.assertj.core.api.AbstractAssert;
import org.junit.Test;

import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.header.ClearSiteDataServerHttpHeadersWriter.Directive;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author MD Sayem Ahmed
 * @since 5.2
 */
public class ClearSiteDataServerHttpHeadersWriterTests {

	@Test
	public void constructorWhenMissingDirectivesThenThrowsException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(ClearSiteDataServerHttpHeadersWriter::new);
	}

	@Test
	public void writeHttpHeadersWhenSecureConnectionThenHeaderWritten() {
		ClearSiteDataServerHttpHeadersWriter writer = new ClearSiteDataServerHttpHeadersWriter(Directive.ALL);
		ServerWebExchange secureExchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("https://localhost").build());

		writer.writeHttpHeaders(secureExchange);

		assertThat(secureExchange.getResponse()).hasClearSiteDataHeaderDirectives(Directive.ALL);
	}

	@Test
	public void writeHttpHeadersWhenInsecureConnectionThenHeaderNotWritten() {
		ClearSiteDataServerHttpHeadersWriter writer = new ClearSiteDataServerHttpHeadersWriter(Directive.ALL);
		ServerWebExchange insecureExchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

		writer.writeHttpHeaders(insecureExchange);

		assertThat(insecureExchange.getResponse()).doesNotHaveClearSiteDataHeaderSet();
	}

	@Test
	public void writeHttpHeadersWhenMultipleDirectivesSpecifiedThenHeaderContainsAll() {
		ClearSiteDataServerHttpHeadersWriter writer = new ClearSiteDataServerHttpHeadersWriter(Directive.CACHE,
				Directive.COOKIES);
		ServerWebExchange secureExchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("https://localhost").build());

		writer.writeHttpHeaders(secureExchange);

		assertThat(secureExchange.getResponse()).hasClearSiteDataHeaderDirectives(Directive.CACHE, Directive.COOKIES);
	}

	private static ClearSiteDataAssert assertThat(ServerHttpResponse response) {
		return new ClearSiteDataAssert(response);
	}

	private static class ClearSiteDataAssert extends AbstractAssert<ClearSiteDataAssert, ServerHttpResponse> {

		ClearSiteDataAssert(ServerHttpResponse response) {
			super(response, ClearSiteDataAssert.class);
		}

		void hasClearSiteDataHeaderDirectives(Directive... directives) {
			isNotNull();
			List<String> header = getHeader();
			String actualHeaderValue = String.join("", header);
			String expectedHeaderVale = Stream.of(directives).map(Directive::getHeaderValue)
					.collect(Collectors.joining(", "));
			if (!actualHeaderValue.equals(expectedHeaderVale)) {
				failWithMessage("Expected to have %s as Clear-Site-Data header value but found %s", expectedHeaderVale,
						actualHeaderValue);
			}
		}

		void doesNotHaveClearSiteDataHeaderSet() {
			isNotNull();
			List<String> header = getHeader();
			if (!CollectionUtils.isEmpty(header)) {
				failWithMessage("Expected not to have Clear-Site-Data header set but found %s",
						String.join("", header));
			}
		}

		List<String> getHeader() {
			return actual.getHeaders().get(ClearSiteDataServerHttpHeadersWriter.CLEAR_SITE_DATA_HEADER);
		}

	}

}
