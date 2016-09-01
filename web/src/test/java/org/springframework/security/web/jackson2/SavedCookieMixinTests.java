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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.web.savedrequest.SavedCookie;

import javax.servlet.http.Cookie;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh.
 */
public class SavedCookieMixinTests extends AbstractMixinTests {

	private String expectedSavedCookieJson;

	@Before
	public void setup() {
		expectedSavedCookieJson = "{\"@class\": \"org.springframework.security.web.savedrequest.SavedCookie\", " +
				"\"name\": \"session\", \"value\": \"123456\", \"comment\": null, \"domain\": null, \"maxAge\": -1, " +
				"\"path\": null, \"secure\": false, \"version\": 0}";
	}


	@Test
	public void serializeWithDefaultConfigurationTest() throws JsonProcessingException, JSONException {
		SavedCookie savedCookie = new SavedCookie(new Cookie("session", "123456"));
		String actualJson = buildObjectMapper().writeValueAsString(savedCookie);
		JSONAssert.assertEquals(expectedSavedCookieJson, actualJson, true);
	}

	@Test
	public void serializeWithOverrideConfigurationTest() throws JsonProcessingException, JSONException {
		SavedCookie savedCookie = new SavedCookie(new Cookie("session", "123456"));
		ObjectMapper mapper = buildObjectMapper();
		mapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY)
				.setVisibility(PropertyAccessor.GETTER, JsonAutoDetect.Visibility.ANY);
		String actualJson = mapper.writeValueAsString(savedCookie);
		JSONAssert.assertEquals(expectedSavedCookieJson, actualJson, true);
	}

	@Test
	public void serializeSavedCookieWithList() throws JsonProcessingException, JSONException {
		List<SavedCookie> savedCookies = new ArrayList<SavedCookie>();
		savedCookies.add(new SavedCookie(new Cookie("session", "123456")));
		String expectedJson = String.format("[\"java.util.ArrayList\", [%s]]", expectedSavedCookieJson);
		String actualJson = buildObjectMapper().writeValueAsString(savedCookies);
		JSONAssert.assertEquals(expectedJson, actualJson, true);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void deserializeSavedCookieWithList() throws IOException, JSONException {
		String expectedJson = String.format("[\"java.util.ArrayList\", [%s]]", expectedSavedCookieJson);
		List<SavedCookie> savedCookies = (List<SavedCookie>)buildObjectMapper().readValue(expectedJson, Object.class);
		assertThat(savedCookies).isNotNull().hasSize(1);
		assertThat(savedCookies.get(0).getName()).isEqualTo("session");
		assertThat(savedCookies.get(0).getValue()).isEqualTo("123456");
	}

	@Test
	public void deserializeSavedCookieJsonTest() throws IOException {
		SavedCookie savedCookie = (SavedCookie) buildObjectMapper().readValue(expectedSavedCookieJson, Object.class);
		assertThat(savedCookie).isNotNull();
		assertThat(savedCookie.getName()).isEqualTo("session");
		assertThat(savedCookie.getValue()).isEqualTo("123456");
		assertThat(savedCookie.isSecure()).isEqualTo(false);
		assertThat(savedCookie.getVersion()).isEqualTo(0);
		assertThat(savedCookie.getComment()).isNull();
	}
}
