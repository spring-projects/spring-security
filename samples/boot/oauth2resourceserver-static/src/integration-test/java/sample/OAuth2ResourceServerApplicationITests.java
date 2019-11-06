/*
 * Copyright 2002-2017 the original author or authors.
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
package sample;

import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for {@link OAuth2ResourceServerApplication}
 *
 * @author Josh Cummings
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class OAuth2ResourceServerApplicationITests {

	String noScopesToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaWF0IjoxNTE2MjM5MDIyfQ.eB2c9xtg5wcCZxZ-o-sH4Mx1JGkqAZwH4_WS0UcDbj_nen0NPBj6CqOEPhr_LZDagb4mM6HoAPJywWWG8b_Ylnn5r2gWDzib2mb0kxIuAjnvVBrpzusw4ItTVvP_srv2DrwcisKYiKqU5X_3ka7MSVvKtswdLY3RXeCJ_S2W9go";
	String messageReadToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaWF0IjoxNTE2MjM5MDIyLCJzY29wZSI6Im1lc3NhZ2U6cmVhZCJ9.bsRCpUEaiWnzX4OqNxTBqwUD4vxxtPp-CHKTw7XcrglrvZ2lvYXaiZZbCp-hcPhuzMEzEAFuH6s4GZZOWVIX-wT47GdTz9cfA-Z4QPjS2RxePKphFXgBI3jHEpQo94Qya2fJdV4LvgBmA1uM_RTnYY1UbmeYuHKnXrZoGyV8QQQ";

	@Autowired
	MockMvc mvc;

	@Test
	public void performWhenValidBearerTokenThenAllows()
		throws Exception {

		this.mvc.perform(get("/").with(bearerToken(this.noScopesToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Hello, subject!")));
	}

	// -- tests with scopes

	@Test
	public void performWhenValidBearerTokenThenScopedRequestsAlsoWork()
			throws Exception {

		this.mvc.perform(get("/message").with(bearerToken(this.messageReadToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("secret message")));
	}

	@Test
	public void performWhenInsufficientlyScopedBearerTokenThenDeniesScopedMethodAccess()
			throws Exception {

		this.mvc.perform(get("/message").with(bearerToken(this.noScopesToken)))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
						containsString("Bearer error=\"insufficient_scope\"")));
	}

	private static class BearerTokenRequestPostProcessor implements RequestPostProcessor {
		private String token;

		BearerTokenRequestPostProcessor(String token) {
			this.token = token;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			request.addHeader("Authorization", "Bearer " + this.token);
			return request;
		}
	}

	private static BearerTokenRequestPostProcessor bearerToken(String token) {
		return new BearerTokenRequestPostProcessor(token);
	}
}
