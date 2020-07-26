/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.util.matcher;

import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */
public class RequestHeaderRequestMatcherTests {

	private final String headerName = "headerName";

	private final String headerValue = "headerValue";

	private MockHttpServletRequest request;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullHeaderName() {
		new RequestHeaderRequestMatcher(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullHeaderNameNonNullHeaderValue() {
		new RequestHeaderRequestMatcher(null, "v");
	}

	@Test
	public void matchesHeaderNameMatches() {
		this.request.addHeader(this.headerName, this.headerValue);
		assertThat(new RequestHeaderRequestMatcher(this.headerName).matches(this.request)).isTrue();
	}

	@Test
	public void matchesHeaderNameDoesNotMatch() {
		this.request.addHeader(this.headerName + "notMatch", this.headerValue);
		assertThat(new RequestHeaderRequestMatcher(this.headerName).matches(this.request)).isFalse();
	}

	@Test
	public void matchesHeaderNameValueMatches() {
		this.request.addHeader(this.headerName, this.headerValue);
		assertThat(new RequestHeaderRequestMatcher(this.headerName, this.headerValue).matches(this.request)).isTrue();
	}

	@Test
	public void matchesHeaderNameValueHeaderNameNotMatch() {
		this.request.addHeader(this.headerName + "notMatch", this.headerValue);
		assertThat(new RequestHeaderRequestMatcher(this.headerName, this.headerValue).matches(this.request)).isFalse();
	}

	@Test
	public void matchesHeaderNameValueHeaderValueNotMatch() {
		this.request.addHeader(this.headerName, this.headerValue + "notMatch");
		assertThat(new RequestHeaderRequestMatcher(this.headerName, this.headerValue).matches(this.request)).isFalse();
	}

	@Test
	public void matchesHeaderNameValueHeaderValueMultiNotMatch() {
		this.request.addHeader(this.headerName, this.headerValue + "notMatch");
		this.request.addHeader(this.headerName, this.headerValue);
		assertThat(new RequestHeaderRequestMatcher(this.headerName, this.headerValue).matches(this.request)).isFalse();
	}

}
