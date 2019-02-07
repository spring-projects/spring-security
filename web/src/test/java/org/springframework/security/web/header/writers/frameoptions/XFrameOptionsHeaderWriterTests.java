/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.web.header.writers.frameoptions;

import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @author Ankur Pathak
 * @since 5.0
 */
public class XFrameOptionsHeaderWriterTests {
	private MockHttpServletRequest request = new MockHttpServletRequest();
	private MockHttpServletResponse response = new MockHttpServletResponse();

	private static final String XFRAME_OPTIONS_HEADER = "X-Frame-Options";

	@Test
	public void writeHeadersWhenWhiteList() {
		WhiteListedAllowFromStrategy whitelist = new WhiteListedAllowFromStrategy(Arrays.asList("example.com"));
		XFrameOptionsHeaderWriter writer = new XFrameOptionsHeaderWriter(whitelist);


		writer.writeHeaders(this.request, this.response);

		assertThat(this.response.getHeaderValue(XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER)).isEqualTo("DENY");
	}

	@Test
	public void writeHeaderWhenNotPresent() {
		WhiteListedAllowFromStrategy whitelist = new WhiteListedAllowFromStrategy(Collections.singletonList("example.com"));
		XFrameOptionsHeaderWriter writer = new XFrameOptionsHeaderWriter(whitelist);
		String value = new String("value");
		this.response.setHeader(XFRAME_OPTIONS_HEADER, value);
		writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(XFRAME_OPTIONS_HEADER)).isSameAs(value);
	}
}
