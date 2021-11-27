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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link FeaturePolicyHeaderWriter}.
 *
 * @author Vedran Pavic
 * @author Ankur Pathak
 */
public class FeaturePolicyHeaderWriterTests {

	private static final String DEFAULT_POLICY_DIRECTIVES = "geolocation 'self'";

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private FeaturePolicyHeaderWriter writer;

	private static final String FEATURE_POLICY_HEADER = "Feature-Policy";

	@BeforeEach
	public void setUp() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.writer = new FeaturePolicyHeaderWriter(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersFeaturePolicyDefault() {
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Feature-Policy")).isEqualTo(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void createWriterWithNullDirectivesShouldThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new FeaturePolicyHeaderWriter(null))
				.withMessage("policyDirectives must not be null or empty");
	}

	@Test
	public void createWriterWithEmptyDirectivesShouldThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new FeaturePolicyHeaderWriter(""))
				.withMessage("policyDirectives must not be null or empty");
	}

	@Test
	public void writeHeaderOnlyIfNotPresent() {
		String value = new String("value");
		this.response.setHeader(FEATURE_POLICY_HEADER, value);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(FEATURE_POLICY_HEADER)).isSameAs(value);
	}

}
