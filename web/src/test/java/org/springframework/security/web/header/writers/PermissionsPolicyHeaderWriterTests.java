/*
 * Copyright 2002-2020 the original author or authors.
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PermissionsPolicyHeaderWriter}.
 *
 * @author Christophe Gilles
 */
public class PermissionsPolicyHeaderWriterTests {

	private static final String DEFAULT_POLICY_DIRECTIVES = "geolocation=(self)";

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private PermissionsPolicyHeaderWriter writer;

	private static final String PERMISSIONS_POLICY_HEADER = "Permissions-Policy";

	@BeforeEach
	public void setUp() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.writer = new PermissionsPolicyHeaderWriter(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersPermissionsPolicyDefault() {
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Permissions-Policy")).isEqualTo(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void createWriterWithNullPolicyShouldThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new PermissionsPolicyHeaderWriter(null))
				.withMessage("policy can not be null or empty");
	}

	@Test
	public void createWriterWithEmptyPolicyShouldThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new PermissionsPolicyHeaderWriter(""))
				.withMessage("policy can not be null or empty");
	}

	@Test
	public void writeHeaderOnlyIfNotPresent() {
		String value = new String("value");
		this.response.setHeader(PERMISSIONS_POLICY_HEADER, value);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(PERMISSIONS_POLICY_HEADER)).isSameAs(value);
	}

}
