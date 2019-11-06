/*
 * Copyright 2002-2019 the original author or authors.
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

	String tenantOneNoScopesToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0IiwiZXhwIjo0NjgzODA1MTI4fQ.ULEPdHG-MK5GlrTQMhgqcyug2brTIZaJIrahUeq9zaiwUSdW83fJ7W1IDd2Z3n4a25JY2uhEcoV95lMfccHR6y_2DLrNvfta22SumY9PEDF2pido54LXG6edIGgarnUbJdR4rpRe_5oRGVa8gDx8FnuZsNv6StSZHAzw5OsuevSTJ1UbJm4UfX3wiahFOQ2OI6G-r5TB2rQNdiPHuNyzG5yznUqRIZ7-GCoMqHMaC-1epKxiX8gYXRROuUYTtcMNa86wh7OVDmvwVmFioRcR58UWBRoO1XQexTtOQq_t8KYsrPZhb9gkyW8x2bAQF-d0J0EJY8JslaH6n4RBaZISww";
	String tenantOneMessageReadToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0Iiwic2NvcGUiOiJtZXNzYWdlOnJlYWQiLCJleHAiOjQ2ODM4MDUxNDF9.h-j6FKRFdnTdmAueTZCdep45e6DPwqM68ZQ8doIJ1exi9YxAlbWzOwId6Bd0L5YmCmp63gGQgsBUBLzwnZQ8kLUgUOBEC3UzSWGRqMskCY9_k9pX0iomX6IfF3N0PaYs0WPC4hO1s8wfZQ-6hKQ4KigFi13G9LMLdH58PRMK0pKEvs3gCbHJuEPw-K5ORlpdnleUTQIwINafU57cmK3KocTeknPAM_L716sCuSYGvDl6xUTXO7oPdrXhS_EhxLP6KxrpI1uD4Ea_5OWTh7S0Wx5LLDfU6wBG1DowN20d374zepOIEkR-Jnmr_QlR44vmRqS5ncrF-1R0EGcPX49U6A";
	String tenantTwoNoScopesToken = "00ed5855-1869-47a0-b0c9-0f3ce520aee7";
	String tenantTwoMessageReadToken = "b43d1500-c405-4dc9-b9c9-6cfd966c34c9";

	@Autowired
	MockMvc mvc;

	@Test
	public void tenantOnePerformWhenValidBearerTokenThenAllows()
		throws Exception {

		this.mvc.perform(get("/tenantOne").with(bearerToken(this.tenantOneNoScopesToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Hello, subject for tenantOne!")));
	}

	@Test
	public void tenantOnePerformWhenValidBearerTokenWithServletPathThenAllows()
		throws Exception {

		this.mvc.perform(get("/tenantOne").servletPath("/tenantOne").with(bearerToken(this.tenantOneNoScopesToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Hello, subject for tenantOne!")));
	}

	// -- tests with scopes

	@Test
	public void tenantOnePerformWhenValidBearerTokenThenScopedRequestsAlsoWork()
			throws Exception {

		this.mvc.perform(get("/tenantOne/message").with(bearerToken(this.tenantOneMessageReadToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("secret message for tenantOne")));
	}

	@Test
	public void tenantOnePerformWhenInsufficientlyScopedBearerTokenThenDeniesScopedMethodAccess()
			throws Exception {

		this.mvc.perform(get("/tenantOne/message").with(bearerToken(this.tenantOneNoScopesToken)))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
						containsString("Bearer error=\"insufficient_scope\"")));
	}

	@Test
	public void tenantTwoPerformWhenValidBearerTokenThenAllows()
			throws Exception {

		this.mvc.perform(get("/tenantTwo").with(bearerToken(this.tenantTwoNoScopesToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Hello, subject for tenantTwo!")));
	}

	// -- tests with scopes

	@Test
	public void tenantTwoPerformWhenValidBearerTokenThenScopedRequestsAlsoWork()
			throws Exception {

		this.mvc.perform(get("/tenantTwo/message").with(bearerToken(this.tenantTwoMessageReadToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("secret message for tenantTwo")));
	}

	@Test
	public void tenantTwoPerformWhenInsufficientlyScopedBearerTokenThenDeniesScopedMethodAccess()
			throws Exception {

		this.mvc.perform(get("/tenantTwo/message").with(bearerToken(this.tenantTwoNoScopesToken)))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
						containsString("Bearer error=\"insufficient_scope\"")));
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidTenantPerformWhenValidBearerTokenThenThrowsException()
			throws Exception {

		this.mvc.perform(get("/tenantThree").with(bearerToken(this.tenantOneNoScopesToken)));
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
