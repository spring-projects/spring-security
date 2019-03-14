/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.taglibs.csrf;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Nick Williams
 */
public class CsrfInputTagTests {

	public CsrfInputTag tag;

	@Before
	public void setUp() {
		this.tag = new CsrfInputTag();
	}

	@Test
	public void handleTokenReturnsHiddenInput() {
		CsrfToken token = new DefaultCsrfToken("X-Csrf-Token", "_csrf",
				"abc123def456ghi789");

		String value = this.tag.handleToken(token);

		assertThat(value).as("The returned value should not be null.").isNotNull();
		assertThat(
				value).withFailMessage("The output is not correct.").isEqualTo("<input type=\"hidden\" name=\"_csrf\" value=\"abc123def456ghi789\" />");
	}

	@Test
	public void handleTokenReturnsHiddenInputDifferentTokenValue() {
		CsrfToken token = new DefaultCsrfToken("X-Csrf-Token", "csrfParameter",
				"fooBarBazQux");

		String value = this.tag.handleToken(token);

		assertThat(value).as("The returned value should not be null.").isNotNull();
		assertThat(value).withFailMessage("The output is not correct.").isEqualTo("<input type=\"hidden\" name=\"csrfParameter\" value=\"fooBarBazQux\" />");
	}
}
