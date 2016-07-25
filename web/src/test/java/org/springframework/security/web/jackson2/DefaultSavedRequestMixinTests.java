/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.json.JSONException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedCookie;

import javax.servlet.http.Cookie;
import java.io.IOException;
import java.util.Collections;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 * @since 4.2
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultSavedRequestMixinTests extends AbstractMixinTests {

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
	public void expectedSerializeTest() throws JsonProcessingException, JSONException {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
		request.setServerPort(8080);
		request.setContextPath("/app");
		request.setCookies(new Cookie("SESSION", "123456789"));
		request.addHeader("x-auth-token", "12");

		DefaultSavedRequest savedRequest = new DefaultSavedRequest(request, new PortResolverImpl());

		String actualString = buildObjectMapper().writeValueAsString(savedRequest);
		String expectedJson = "{\"@class\":\"org.springframework.security.web.savedrequest.DefaultSavedRequest\",\"contextPath\": \"/app\", \"cookies\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.web.savedrequest.SavedCookie\", \"name\": \"SESSION\", \"value\": \"123456789\", \"secure\": false, \"version\": 0, \"maxAge\": -1, \"comment\": null, \"domain\": null, \"path\": null}]],\n" +
				"\"locales\": [\"java.util.ArrayList\", [\"en\"]], \"method\": \"POST\", \"pathInfo\": null, \"queryString\": null, \"requestURI\": \"/login\", \"requestURL\": \"http://localhost:8080/login\",\n" +
				"\"scheme\": \"http\",  \"serverName\": \"localhost\", \"serverPort\": 8080, \"servletPath\": \"\", \"parameters\": {\"@class\": \"java.util.TreeMap\"}," +
				"\"headers\": {\"@class\": \"java.util.TreeMap\", \"x-auth-token\": [\"java.util.ArrayList\", [\"12\"]]}}";
		JSONAssert.assertEquals(expectedJson, actualString, true);
	}


	@Test
	public void serializeDefaultRequestBuildWithConstructorTest() throws IOException, JSONException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(new Cookie("SESSION", "123456789"));
		request.addHeader("x-auth-token", "12");

		String expectedJsonString = "{" +
					"\"@class\": \"org.springframework.security.web.savedrequest.DefaultSavedRequest\", \"cookies\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.web.savedrequest.SavedCookie\", \"name\": \"SESSION\", \"value\": \"123456789\", \"comment\": null, \"maxAge\": -1, \"path\": null, \"secure\":false, \"version\": 0, \"domain\": null}]]," +
					"\"locales\": [\"java.util.ArrayList\", [\"en\"]], \"headers\": {\"@class\": \"java.util.TreeMap\", \"x-auth-token\": [\"java.util.ArrayList\", [\"12\"]]}, \"parameters\": {\"@class\": \"java.util.TreeMap\"}," +
					"\"contextPath\": \"\", \"method\": \"\", \"pathInfo\": null, \"queryString\": null, \"requestURI\": \"\", \"requestURL\": \"http://localhost\", \"scheme\": \"http\", " +
					"\"serverName\": \"localhost\", \"servletPath\": \"\", \"serverPort\": 80"+
				"}";
		String actualString = buildObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(new DefaultSavedRequest(request, new PortResolverImpl()));
		JSONAssert.assertEquals(expectedJsonString, actualString, true);
	}

	@Test
	public void serializeDefaultRequestBuildWithBuilderTest() throws IOException, JSONException {
		DefaultSavedRequest request = new DefaultSavedRequest.Builder()
				.setCookies(Collections.singletonList(new SavedCookie(new Cookie("SESSION", "123456789"))))
				.setHeaders(Collections.singletonMap("x-auth-token", Collections.singletonList("12")))
				.setScheme("http").setRequestURL("http://localhost").setServerName("localhost").setRequestURI("")
				.setLocales(Collections.singletonList(new Locale("en"))).setContextPath("").setMethod("")
				.setServletPath("").build();

		String expectedJsonString = "{" +
					"\"@class\": \"org.springframework.security.web.savedrequest.DefaultSavedRequest\", \"cookies\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.web.savedrequest.SavedCookie\", \"name\": \"SESSION\", \"value\": \"123456789\", \"comment\": null, \"maxAge\": -1, \"path\": null, \"secure\":false, \"version\": 0, \"domain\": null}]]," +
					"\"locales\": [\"java.util.ArrayList\", [\"en\"]], \"headers\": {\"@class\": \"java.util.TreeMap\", \"x-auth-token\": [\"java.util.ArrayList\", [\"12\"]]}, \"parameters\": {\"@class\": \"java.util.TreeMap\"}," +
					"\"contextPath\": \"\", \"method\": \"\", \"pathInfo\": null, \"queryString\": null, \"requestURI\": \"\", \"requestURL\": \"http://localhost\", \"scheme\": \"http\", " +
					"\"serverName\": \"localhost\", \"servletPath\": \"\", \"serverPort\": 80"+
				"}";
		String actualString = buildObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(request);
		JSONAssert.assertEquals(expectedJsonString, actualString, true);
	}

	@Test
	public void deserializeDefaultSavedRequest() throws IOException {
		String jsonString = "{" +
				"\"@class\": \"org.springframework.security.web.savedrequest.DefaultSavedRequest\", \"cookies\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.web.savedrequest.SavedCookie\", \"name\": \"SESSION\", \"value\": \"123456789\", \"comment\": null, \"maxAge\": -1, \"path\": null, \"secure\":false, \"version\": 0, \"isHttpOnly\": false, \"domain\": null}]]," +
				"\"locales\": [\"java.util.ArrayList\", [\"en\"]], \"headers\": {\"@class\": \"java.util.TreeMap\", \"x-auth-token\": [\"java.util.ArrayList\", [\"12\"]]}, \"parameters\": {\"@class\": \"java.util.TreeMap\"}," +
				"\"contextPath\": \"\", \"method\": \"\", \"pathInfo\": null, \"queryString\": null, \"requestURI\": \"\", \"requestURL\": \"http://localhost\", \"scheme\": \"http\", " +
				"\"serverName\": \"localhost\", \"servletPath\": \"\", \"serverPort\": 80" +
				"}";
		DefaultSavedRequest request = (DefaultSavedRequest) buildObjectMapper().readValue(jsonString, Object.class);
		assertThat(request).isNotNull();
		assertThat(request.getCookies()).hasSize(1);
		assertThat(request.getLocales()).hasSize(1).contains(new Locale("en"));
		assertThat(request.getHeaderNames()).hasSize(1).contains("x-auth-token");
		assertThat(request.getHeaderValues("x-auth-token")).hasSize(1).contains("12");
	}
}
