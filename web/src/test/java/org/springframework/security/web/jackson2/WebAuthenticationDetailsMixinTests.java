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

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.jackson2.SecurityJacksonModules;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 * @since 4.2
 */
@RunWith(MockitoJUnitRunner.class)
public class WebAuthenticationDetailsMixinTests {

	ObjectMapper mapper;
	String webAuthenticationDetailsJson = "{\"@class\": \"org.springframework.security.web.authentication.WebAuthenticationDetails\","
			+ "\"sessionId\": \"1\", \"remoteAddress\": \"/localhost\"}";

	@Before
	public void setup() {
		this.mapper = new ObjectMapper();
		ClassLoader loader = getClass().getClassLoader();
		this.mapper.registerModules(SecurityJacksonModules.getModules(loader));
	}

	@Test
	public void buildWebAuthenticationDetailsUsingDifferentConstructors()
			throws IOException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr("localhost");
		request.setSession(new MockHttpSession(null, "1"));

		WebAuthenticationDetails details = new WebAuthenticationDetails(request);

		WebAuthenticationDetails authenticationDetails = this.mapper.readValue(webAuthenticationDetailsJson,
				WebAuthenticationDetails.class);
		assertThat(details.equals(authenticationDetails));
	}

	@Test
	public void webAuthenticationDetailsSerializeTest()
			throws JsonProcessingException, JSONException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr("/localhost");
		request.setSession(new MockHttpSession(null, "1"));
		WebAuthenticationDetails details = new WebAuthenticationDetails(request);
		String actualJson = this.mapper.writeValueAsString(details);
		JSONAssert.assertEquals(webAuthenticationDetailsJson, actualJson, true);
	}

	@Test
	public void webAuthenticationDetailsDeserializeTest()
			throws IOException, JSONException {
		WebAuthenticationDetails details = this.mapper.readValue(webAuthenticationDetailsJson,
				WebAuthenticationDetails.class);
		assertThat(details).isNotNull();
		assertThat(details.getRemoteAddress()).isEqualTo("/localhost");
		assertThat(details.getSessionId()).isEqualTo("1");
	}
}
