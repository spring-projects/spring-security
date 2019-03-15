/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.web.header.writers;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Joe Grandja
 */
public class ContentSecurityPolicyHeaderWriterTests {
	private static final String DEFAULT_POLICY_DIRECTIVES = "default-src 'self'";
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;
	private ContentSecurityPolicyHeaderWriter writer;

	@Before
	public void setup() {
		request = new MockHttpServletRequest();
		request.setSecure(true);
		response = new MockHttpServletResponse();
		writer = new ContentSecurityPolicyHeaderWriter(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersContentSecurityPolicyDefault() {
		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Content-Security-Policy")).isEqualTo(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersContentSecurityPolicyCustom() {
		String policyDirectives = "default-src 'self'; " +
				"object-src plugins1.example.com plugins2.example.com; " +
				"script-src trustedscripts.example.com";

		writer = new ContentSecurityPolicyHeaderWriter(policyDirectives);
		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Content-Security-Policy")).isEqualTo(policyDirectives);
	}

	@Test
	public void writeHeadersContentSecurityPolicyReportOnlyDefault() {
		writer.setReportOnly(true);
		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Content-Security-Policy-Report-Only")).isEqualTo(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersContentSecurityPolicyReportOnlyCustom() {
		String policyDirectives = "default-src https:; report-uri https://example.com/";

		writer = new ContentSecurityPolicyHeaderWriter(policyDirectives);
		writer.setReportOnly(true);
		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Content-Security-Policy-Report-Only")).isEqualTo(policyDirectives);
	}

	@Test(expected = IllegalArgumentException.class)
	public void writeHeadersContentSecurityPolicyInvalid() {
		writer = new ContentSecurityPolicyHeaderWriter("");
		writer = new ContentSecurityPolicyHeaderWriter(null);
	}

}