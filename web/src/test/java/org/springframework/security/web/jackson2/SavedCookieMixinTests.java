/*
 * Copyright 2015-2017 the original author or authors.
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
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.Cookie;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.web.savedrequest.SavedCookie;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh.
 */
public class SavedCookieMixinTests extends AbstractMixinTests {

	// @formatter:off
	private static final String COOKIE_JSON = "{"
		+ "\"@class\": \"org.springframework.security.web.savedrequest.SavedCookie\", "
		+ "\"name\": \"SESSION\", "
		+ "\"value\": \"123456789\", "
		+ "\"comment\": null, "
		+ "\"maxAge\": -1, "
		+ "\"path\": null, "
		+ "\"secure\":false, "
		+ "\"version\": 0, "
		+ "\"domain\": null"
	+ "}";
	// @formatter:on

	// @formatter:off
	private static final String COOKIES_JSON = "[\"java.util.ArrayList\", ["
		+ COOKIE_JSON
	+ "]]";
	// @formatter:on

	@Test
	public void serializeWithDefaultConfigurationTest() throws JsonProcessingException, JSONException {
		SavedCookie savedCookie = new SavedCookie(new Cookie("SESSION", "123456789"));
		String actualJson = this.mapper.writeValueAsString(savedCookie);
		JSONAssert.assertEquals(COOKIE_JSON, actualJson, true);
	}

	@Test
	public void serializeWithOverrideConfigurationTest() throws JsonProcessingException, JSONException {
		SavedCookie savedCookie = new SavedCookie(new Cookie("SESSION", "123456789"));
		this.mapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY)
				.setVisibility(PropertyAccessor.GETTER, JsonAutoDetect.Visibility.ANY);
		String actualJson = this.mapper.writeValueAsString(savedCookie);
		JSONAssert.assertEquals(COOKIE_JSON, actualJson, true);
	}

	@Test
	public void serializeSavedCookieWithList() throws JsonProcessingException, JSONException {
		List<SavedCookie> savedCookies = new ArrayList<>();
		savedCookies.add(new SavedCookie(new Cookie("SESSION", "123456789")));
		String actualJson = this.mapper.writeValueAsString(savedCookies);
		JSONAssert.assertEquals(COOKIES_JSON, actualJson, true);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void deserializeSavedCookieWithList() throws IOException {
		List<SavedCookie> savedCookies = (List<SavedCookie>) this.mapper.readValue(COOKIES_JSON, Object.class);
		assertThat(savedCookies).isNotNull().hasSize(1);
		assertThat(savedCookies.get(0).getName()).isEqualTo("SESSION");
		assertThat(savedCookies.get(0).getValue()).isEqualTo("123456789");
	}

	@Test
	public void deserializeSavedCookieJsonTest() throws IOException {
		SavedCookie savedCookie = (SavedCookie) this.mapper.readValue(COOKIE_JSON, Object.class);
		assertThat(savedCookie).isNotNull();
		assertThat(savedCookie.getName()).isEqualTo("SESSION");
		assertThat(savedCookie.getValue()).isEqualTo("123456789");
		assertThat(savedCookie.isSecure()).isEqualTo(false);
		assertThat(savedCookie.getVersion()).isZero();
		assertThat(savedCookie.getComment()).isNull();
	}

}
