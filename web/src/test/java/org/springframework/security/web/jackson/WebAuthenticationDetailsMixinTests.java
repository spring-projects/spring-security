/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.jackson;

import org.json.JSONException;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import tools.jackson.core.JacksonException;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 * @since 4.2
 */
public class WebAuthenticationDetailsMixinTests extends AbstractMixinTests {

	// @formatter:off
	private static final String AUTHENTICATION_DETAILS_JSON = "{"
		+ "\"@class\": \"org.springframework.security.web.authentication.WebAuthenticationDetails\","
		+ "\"sessionId\": \"1\", "
		+ "\"remoteAddress\": "
		+ "\"/localhost\""
	+ "}";
	// @formatter:on
	@Test
	public void buildWebAuthenticationDetailsUsingDifferentConstructors() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr("localhost");
		request.setSession(new MockHttpSession(null, "1"));
		WebAuthenticationDetails details = new WebAuthenticationDetails(request);
		WebAuthenticationDetails authenticationDetails = this.mapper.readValue(AUTHENTICATION_DETAILS_JSON,
				WebAuthenticationDetails.class);
		assertThat(details.equals(authenticationDetails));
	}

	@Test
	public void webAuthenticationDetailsSerializeTest() throws JacksonException, JSONException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr("/localhost");
		request.setSession(new MockHttpSession(null, "1"));
		WebAuthenticationDetails details = new WebAuthenticationDetails(request);
		String actualJson = this.mapper.writeValueAsString(details);
		JSONAssert.assertEquals(AUTHENTICATION_DETAILS_JSON, actualJson, true);
	}

	@Test
	public void webAuthenticationDetailsJackson2SerializeTest() throws JacksonException, JSONException {
		WebAuthenticationDetails details = new WebAuthenticationDetails("/localhost", "1");
		String actualJson = this.mapper.writeValueAsString(details);
		JSONAssert.assertEquals(AUTHENTICATION_DETAILS_JSON, actualJson, true);
	}

	@Test
	public void webAuthenticationDetailsDeserializeTest() {
		WebAuthenticationDetails details = this.mapper.readValue(AUTHENTICATION_DETAILS_JSON,
				WebAuthenticationDetails.class);
		assertThat(details).isNotNull();
		assertThat(details.getRemoteAddress()).isEqualTo("/localhost");
		assertThat(details.getSessionId()).isEqualTo("1");
	}

}
