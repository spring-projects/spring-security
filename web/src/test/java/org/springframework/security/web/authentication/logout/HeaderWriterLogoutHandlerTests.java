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

package org.springframework.security.web.authentication.logout;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 *
 * @author Rafiullah Hamedy
 *
 * @see {@link HeaderWriterLogoutHandler}
 */
public class HeaderWriterLogoutHandlerTests {
	private static final String HEADER_NAME = "Clear-Site-Data";

	private MockHttpServletResponse response;
	private MockHttpServletRequest request;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Before
	public void setup() {
		this.response = new MockHttpServletResponse();
		this.request = new MockHttpServletRequest();
	}

	@Test
	public void createInstanceWhenHeaderWriterIsNullThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("headerWriter cannot be null.");

		new HeaderWriterLogoutHandler(null);
	}

	@Test
	public void createInstanceWhenSourceIsNullThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Sources cannot be empty or null.");

		new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter());
	}

	@Test
	public void logoutWhenRequestIsNotSecureThenHeaderIsNotPresent() {
		HeaderWriterLogoutHandler handler = new HeaderWriterLogoutHandler(
				new ClearSiteDataHeaderWriter("cache"));

		handler.logout(request, response, mock(Authentication.class));

		assertThat(header().doesNotExist(HEADER_NAME));
	}

	@Test
	public void logoutWhenRequestIsSecureThenHeaderIsPresentMatchesWildCardSource() {
		HeaderWriterLogoutHandler handler = new HeaderWriterLogoutHandler(
				new ClearSiteDataHeaderWriter("*"));

		this.request.setSecure(true);

		handler.logout(request, response, mock(Authentication.class));

		assertThat(header().stringValues(HEADER_NAME, "\"*\""));
	}

	@Test
	public void logoutWhenRequestIsSecureThenHeaderValueMatchesSource() {
		HeaderWriterLogoutHandler handler = new HeaderWriterLogoutHandler(
				new ClearSiteDataHeaderWriter("cache", "cookies", "storage",
						"executionContexts"));

		this.request.setSecure(true);

		handler.logout(request, response, mock(Authentication.class));

		assertThat(header().stringValues(HEADER_NAME, "\"cache\", \"cookies\", \"storage\", "
				+ "\"executionContexts\""));
	}
}
