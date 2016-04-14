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
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import javax.servlet.http.Cookie;
import java.io.IOException;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Jitendra Singh
 */
public class CookieMixinTest {

	ObjectMapper buildObjectMapper() {
		return new ObjectMapper()
				.addMixIn(Cookie.class, CookieMixin.class);
	}

	@Test
	public void serializeCookie() throws JsonProcessingException, JSONException {
		Cookie cookie = new Cookie("demo", "cookie1");
		String expectedString = "{\"@class\": \"javax.servlet.http.Cookie\", \"name\": \"demo\", \"value\": \"cookie1\"," +
				"\"comment\": null, \"maxAge\": -1, \"path\": null, \"secure\": false, \"version\": 0, \"isHttpOnly\": false, \"domain\": null}";
		String actualString = buildObjectMapper().writeValueAsString(cookie);
		JSONAssert.assertEquals(expectedString, actualString, true);
	}

	@Test
	public void deserializeCookie() throws IOException {
		String cookieString = "{\"@class\": \"javax.servlet.http.Cookie\", \"name\": \"demo\", \"value\": \"cookie1\"," +
				"\"comment\": null, \"maxAge\": -1, \"path\": null, \"secure\": false, \"version\": 0, \"isHttpOnly\": false, \"domain\": null}";
		Cookie cookie = buildObjectMapper().readValue(cookieString, Cookie.class);
		assertThat(cookie).isNotNull();
		assertThat(cookie.getName()).isEqualTo("demo");
		assertThat(cookie.getDomain()).isEqualTo("");
		assertThat(cookie.isHttpOnly()).isEqualTo(false);
	}
}
