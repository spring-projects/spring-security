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

import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.http.Cookie;
import org.json.JSONException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import tools.jackson.core.JacksonException;

import org.springframework.security.web.savedrequest.SavedCookie;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 */
public class SavedCookieMixinTests extends AbstractMixinTests {

	// @formatter:off
	private static final String COOKIE_JSON = "{"
		+ "\"@class\": \"org.springframework.security.web.savedrequest.SavedCookie\", "
		+ "\"name\": \"SESSION\", "
		+ "\"value\": \"123456789\", "
		+ "\"maxAge\": -1, "
		+ "\"path\": null, "
		+ "\"secure\":false, "
		+ "\"domain\": null"
	+ "}";
	// @formatter:on
	// @formatter:off
	private static final String COOKIES_JSON = "[\"java.util.ArrayList\", ["
		+ COOKIE_JSON
	+ "]]";
	// @formatter:on
	@Test
	public void serializeWithDefaultConfigurationTest() throws JacksonException, JSONException {
		SavedCookie savedCookie = new SavedCookie(new Cookie("SESSION", "123456789"));
		String actualJson = this.mapper.writeValueAsString(savedCookie);
		JSONAssert.assertEquals(COOKIE_JSON, actualJson, true);
	}

	@Test
	@Disabled("No supported by Jackson 3 as ObjectMapper/JsonMapper is immutable")
	public void serializeWithOverrideConfigurationTest() throws JacksonException, JSONException {
		SavedCookie savedCookie = new SavedCookie(new Cookie("SESSION", "123456789"));
		// this.mapper.setVisibility(PropertyAccessor.FIELD,
		// JsonAutoDetect.Visibility.PUBLIC_ONLY)
		// .setVisibility(PropertyAccessor.GETTER, JsonAutoDetect.Visibility.ANY);
		String actualJson = this.mapper.writeValueAsString(savedCookie);
		JSONAssert.assertEquals(COOKIE_JSON, actualJson, true);
	}

	@Test
	public void serializeSavedCookieWithList() throws JacksonException, JSONException {
		List<SavedCookie> savedCookies = new ArrayList<>();
		savedCookies.add(new SavedCookie(new Cookie("SESSION", "123456789")));
		String actualJson = this.mapper.writeValueAsString(savedCookies);
		JSONAssert.assertEquals(COOKIES_JSON, actualJson, true);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void deserializeSavedCookieWithList() {
		List<SavedCookie> savedCookies = (List<SavedCookie>) this.mapper.readValue(COOKIES_JSON, Object.class);
		assertThat(savedCookies).isNotNull().hasSize(1);
		assertThat(savedCookies.get(0).getName()).isEqualTo("SESSION");
		assertThat(savedCookies.get(0).getValue()).isEqualTo("123456789");
	}

	@Test
	public void deserializeSavedCookieJsonTest() {
		SavedCookie savedCookie = (SavedCookie) this.mapper.readValue(COOKIE_JSON, Object.class);
		assertThat(savedCookie).isNotNull();
		assertThat(savedCookie.getName()).isEqualTo("SESSION");
		assertThat(savedCookie.getValue()).isEqualTo("123456789");
		assertThat(savedCookie.isSecure()).isEqualTo(false);
	}

}
