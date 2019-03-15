/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.web.jackson2;

import java.io.IOException;
import java.util.Collections;
import java.util.Locale;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedCookie;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 * @since 4.2
 */
public class DefaultSavedRequestMixinTests extends AbstractMixinTests {


	// @formatter:off
	private static final String COOKIES_JSON = "[\"java.util.ArrayList\", [{"
		+ "\"@class\": \"org.springframework.security.web.savedrequest.SavedCookie\", "
		+ "\"name\": \"SESSION\", "
		+ "\"value\": \"123456789\", "
		+ "\"comment\": null, "
		+ "\"maxAge\": -1, "
		+ "\"path\": null, "
		+ "\"secure\":false, "
		+ "\"version\": 0, "
		+ "\"domain\": null"
	+ "}]]";
	// @formatter:on

	// @formatter:off
	private static final String REQUEST_JSON = "{" +
		"\"@class\": \"org.springframework.security.web.savedrequest.DefaultSavedRequest\", "
		+ "\"cookies\": "+ COOKIES_JSON +","
		+ "\"locales\": [\"java.util.ArrayList\", [\"en\"]], "
		+ "\"headers\": {\"@class\": \"java.util.TreeMap\", \"x-auth-token\": [\"java.util.ArrayList\", [\"12\"]]}, "
		+ "\"parameters\": {\"@class\": \"java.util.TreeMap\"},"
		+ "\"contextPath\": \"\", "
		+ "\"method\": \"\", "
		+ "\"pathInfo\": null, "
		+ "\"queryString\": null, "
		+ "\"requestURI\": \"\", "
		+ "\"requestURL\": \"http://localhost\", "
		+ "\"scheme\": \"http\", "
		+ "\"serverName\": \"localhost\", "
		+ "\"servletPath\": \"\", "
		+ "\"serverPort\": 80"
	+ "}";
	// @formatter:on

	@Test
	public void matchRequestBuildWithConstructorAndBuilder() {
		DefaultSavedRequest request = new DefaultSavedRequest.Builder()
				.setCookies(Collections.singletonList(new SavedCookie(new Cookie("SESSION", "123456789"))))
				.setHeaders(Collections.singletonMap("x-auth-token", Collections.singletonList("12")))
				.setScheme("http").setRequestURL("http://localhost").setServerName("localhost").setRequestURI("")
				.setLocales(Collections.singletonList(new Locale("en"))).setContextPath("").setMethod("")
				.setServletPath("").build();
		MockHttpServletRequest mockRequest = new MockHttpServletRequest();
		mockRequest.setCookies(new Cookie("SESSION", "123456789"));
		mockRequest.addHeader("x-auth-token", "12");

		assert request.doesRequestMatch(mockRequest, new PortResolverImpl());
	}

	@Test
	public void serializeDefaultRequestBuildWithConstructorTest() throws IOException, JSONException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("x-auth-token", "12");
		// Spring 5 MockHttpServletRequest automatically adds a header when the cookies are set. To get consistency we override the request.
		HttpServletRequest requestToWrite = new HttpServletRequestWrapper(request) {
			@Override
			public Cookie[] getCookies() {
				return new Cookie[] { new Cookie("SESSION", "123456789") };
			}
		};
		String actualString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(new DefaultSavedRequest(requestToWrite, new PortResolverImpl()));
		JSONAssert.assertEquals(REQUEST_JSON, actualString, true);
	}

	@Test
	public void serializeDefaultRequestBuildWithBuilderTest() throws IOException, JSONException {
		DefaultSavedRequest request = new DefaultSavedRequest.Builder()
				.setCookies(Collections.singletonList(new SavedCookie(new Cookie("SESSION", "123456789"))))
				.setHeaders(Collections.singletonMap("x-auth-token", Collections.singletonList("12")))
				.setScheme("http").setRequestURL("http://localhost").setServerName("localhost").setRequestURI("")
				.setLocales(Collections.singletonList(new Locale("en"))).setContextPath("").setMethod("")
				.setServletPath("").build();
		String actualString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(request);
		JSONAssert.assertEquals(REQUEST_JSON, actualString, true);
	}

	@Test
	public void deserializeDefaultSavedRequest() throws IOException {
		DefaultSavedRequest request = (DefaultSavedRequest) mapper.readValue(REQUEST_JSON, Object.class);
		assertThat(request).isNotNull();
		assertThat(request.getCookies()).hasSize(1);
		assertThat(request.getLocales()).hasSize(1).contains(new Locale("en"));
		assertThat(request.getHeaderNames()).hasSize(1).contains("x-auth-token");
		assertThat(request.getHeaderValues("x-auth-token")).hasSize(1).contains("12");
	}
}
