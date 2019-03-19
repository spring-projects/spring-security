/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package sample;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.security.test.context.support.oauth2.request.OAuth2MockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.context.support.oauth2.request.OAuth2MockMvcRequestPostProcessors.oidcIdToken;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collections;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.context.support.oauth2.annotations.Attribute;
import org.springframework.security.test.context.support.oauth2.annotations.TargetType;
import org.springframework.security.test.context.support.oauth2.annotations.WithMockJwt;
import org.springframework.security.test.context.support.oauth2.annotations.WithMockOidcIdToken;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
@RunWith(SpringRunner.class)
@WebMvcTest(OAuth2ResourceServerController.class)
public class OAuth2ResourceServerControllerTest {

	@Autowired
	MockMvc mockMvc;

	@MockBean
	JwtDecoder jwtDecoder;

	@Test
	@WithMockJwt(name = "subject")
	public void testIndexJwt() throws Exception {
		mockMvc.perform(get("/"))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("Hello, subject!")));
	}

	@Test
	@WithMockOidcIdToken(name = "subject")
	public void testIndexOidcId() throws Exception {
		mockMvc.perform(get("/"))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("Hello, subject!")));
	}

	@Test
	@WithMockJwt("SCOPE_message:read")
	public void testMessageIsAcciessibleWithCorrectJwtScopeAuthority() throws Exception {
		mockMvc.perform(get("/message"))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("secret message")));
	}

	@Test
	@WithMockOidcIdToken("SCOPE_message:read")
	public void testMessageIsAcciessibleWithCorrectOidcIdScopeAuthority()
			throws Exception {
		mockMvc.perform(get("/message"))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("secret message")));
	}

	@Test
	@WithMockJwt(
			claims = @Attribute(
					name = "scope",
					value = "message:read",
					parseTo = TargetType.STRING_SET))
	public void testMessageIsAcciessibleWithCorrectJwtScopeClaim() throws Exception {
		mockMvc.perform(get("/message"))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("secret message")));
	}

	@Test
	@WithMockOidcIdToken(
			claims = @Attribute(
					name = "scope",
					value = "message:read",
					parseTo = TargetType.STRING_SET))
	public void testMessageIsAcciessibleWithCorrectOidcIdScopeClaim() throws Exception {
		mockMvc.perform(get("/message"))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("secret message")));
	}

	@Test
	@WithMockJwt
	public void testMessageIsNotAcciessibleWithDefaultJwtAuthority() throws Exception {
		mockMvc.perform(get("/message")).andDo(print()).andExpect(status().isForbidden());
	}

	@Test
	@WithMockOidcIdToken
	public void testMessageIsNotAcciessibleWithDefaultOidcIdAuthority() throws Exception {
		mockMvc.perform(get("/message")).andDo(print()).andExpect(status().isForbidden());
	}

	@Test
	public void testJwtRequestPostProcessor() throws Exception {
		// No post-processor => no authorization => unauthorized
		mockMvc.perform(get("/message"))
				.andDo(print())
				.andExpect(status().isUnauthorized());

		mockMvc.perform(get("/").with(jwt().name("ch4mpy")))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("Hello, ch4mpy!")));

		mockMvc.perform(get("/message").with(jwt().scope("message:read")))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("secret message")));

		mockMvc.perform(get("/message").with(jwt().authority("SCOPE_message:read")))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("secret message")));

		mockMvc.perform(
				get("/message").with(
						jwt().claim("scope", Collections.singletonList("message:read"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("secret message")));

		mockMvc.perform(get("/message").with(jwt().name("ch4mpy")))
				.andDo(print())
				.andExpect(status().isForbidden());
	}

	@Test
	public void testOidcIdTokenRequestPostProcessor() throws Exception {
		// No post-processor => no authorization => unauthorized
		mockMvc.perform(get("/message"))
				.andDo(print())
				.andExpect(status().isUnauthorized());

		mockMvc.perform(get("/").with(oidcIdToken().name("ch4mpy")))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("Hello, ch4mpy!")));

		mockMvc.perform(get("/message").with(oidcIdToken().scope("message:read")))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("secret message")));

		mockMvc.perform(
				get("/message").with(oidcIdToken().authority("SCOPE_message:read")))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("secret message")));

		mockMvc.perform(
				get("/message").with(
						oidcIdToken().claim(
								"scope",
								Collections.singletonList("message:read"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("secret message")));

		mockMvc.perform(get("/message").with(oidcIdToken().name("ch4mpy")))
				.andDo(print())
				.andExpect(status().isForbidden());
	}

}
