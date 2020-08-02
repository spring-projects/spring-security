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

package org.springframework.security.web.header.writers;

import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Joe Grandja
 * @author Ankur Pathak
 */
public class ContentSecurityPolicyHeaderWriterTests {

	private static final String DEFAULT_POLICY_DIRECTIVES = "default-src 'self'";

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private ContentSecurityPolicyHeaderWriter writer;

	private static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";

	private static final String CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.request.setSecure(true);
		this.response = new MockHttpServletResponse();
		this.writer = new ContentSecurityPolicyHeaderWriter(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersWhenNoPolicyDirectivesThenUsesDefault() {
		ContentSecurityPolicyHeaderWriter noPolicyWriter = new ContentSecurityPolicyHeaderWriter();
		noPolicyWriter.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Content-Security-Policy")).isEqualTo(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersContentSecurityPolicyDefault() {
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Content-Security-Policy")).isEqualTo(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersContentSecurityPolicyCustom() {
		String policyDirectives = "default-src 'self'; " + "object-src plugins1.example.com plugins2.example.com; "
				+ "script-src trustedscripts.example.com";
		this.writer = new ContentSecurityPolicyHeaderWriter(policyDirectives);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Content-Security-Policy")).isEqualTo(policyDirectives);
	}

	@Test
	public void writeHeadersWhenNoPolicyDirectivesReportOnlyThenUsesDefault() {
		ContentSecurityPolicyHeaderWriter noPolicyWriter = new ContentSecurityPolicyHeaderWriter();
		this.writer.setReportOnly(true);
		noPolicyWriter.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Content-Security-Policy")).isEqualTo(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersContentSecurityPolicyReportOnlyDefault() {
		this.writer.setReportOnly(true);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Content-Security-Policy-Report-Only")).isEqualTo(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersContentSecurityPolicyReportOnlyCustom() {
		String policyDirectives = "default-src https:; report-uri https://example.com/";
		this.writer = new ContentSecurityPolicyHeaderWriter(policyDirectives);
		this.writer.setReportOnly(true);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Content-Security-Policy-Report-Only")).isEqualTo(policyDirectives);
	}

	@Test(expected = IllegalArgumentException.class)
	public void writeHeadersContentSecurityPolicyInvalid() {
		this.writer = new ContentSecurityPolicyHeaderWriter("");
		this.writer = new ContentSecurityPolicyHeaderWriter(null);
	}

	@Test
	public void writeContentSecurityPolicyHeaderWhenNotPresent() {
		String value = new String("value");
		this.response.setHeader(CONTENT_SECURITY_POLICY_HEADER, value);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(CONTENT_SECURITY_POLICY_HEADER)).isSameAs(value);
	}

	@Test
	public void writeContentSecurityPolicyReportOnlyHeaderWhenNotPresent() {
		String value = new String("value");
		this.response.setHeader(CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER, value);
		this.writer.setReportOnly(true);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER)).isSameAs(value);
	}

}
