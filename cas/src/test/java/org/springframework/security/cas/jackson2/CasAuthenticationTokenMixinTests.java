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

package org.springframework.security.cas.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jasig.cas.client.authentication.AttributePrincipalImpl;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.json.JSONException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.jackson2.SecurityJacksonModules;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 * @since 4.2
 */
@RunWith(MockitoJUnitRunner.class)
public class CasAuthenticationTokenMixinTests {

	private final String KEY = "casKey";
	private final String PASSWORD = "pass";
	Date startDate = new Date();
	Date endDate = new Date();
	String expectedJson = "{\"@class\": \"org.springframework.security.cas.authentication.CasAuthenticationToken\", \"keyHash\": " + KEY.hashCode() + "," +
			"\"principal\": {\"@class\": \"org.springframework.security.core.userdetails.User\", \"username\": \"username\", \"password\": %s, \"accountNonExpired\": true, \"enabled\": true," +
			"\"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\"," +
			"[{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"USER\"}]]}, \"credentials\": \"" + PASSWORD + "\", \"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]," +
			"\"userDetails\": {\"@class\": \"org.springframework.security.core.userdetails.User\",\"username\": \"user\", \"password\": \"" + PASSWORD + "\", \"enabled\": true, \"accountNonExpired\": true, \"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}," +
			"\"authenticated\": true, \"details\": null," +
			"\"assertion\": {" +
			"\"@class\": \"org.jasig.cas.client.validation.AssertionImpl\", \"principal\": {\"@class\": \"org.jasig.cas.client.authentication.AttributePrincipalImpl\", \"name\": \"assertName\", \"attributes\": {\"@class\": \"java.util.Collections$EmptyMap\"}, \"proxyGrantingTicket\": null, \"proxyRetriever\": null}, " +
			"\"validFromDate\": [\"java.util.Date\", " + startDate.getTime() + "], \"validUntilDate\": [\"java.util.Date\", " + endDate.getTime() + "]," +
			"\"authenticationDate\": [\"java.util.Date\", " + startDate.getTime() + "], \"attributes\": {\"@class\": \"java.util.Collections$EmptyMap\"}" +
			"}}";

	private CasAuthenticationToken createCasAuthenticationToken() {
		User principal = new User("username", PASSWORD, Collections.singletonList(new SimpleGrantedAuthority("USER")));
		Collection<? extends GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
		Assertion assertion = new AssertionImpl(new AttributePrincipalImpl("assertName"), startDate, endDate, startDate, Collections.<String, Object>emptyMap());
		return new CasAuthenticationToken(KEY, principal, principal.getPassword(), authorities,
				new User("user", PASSWORD, authorities), assertion);
	}

	ObjectMapper buildObjectMapper() {
		ObjectMapper mapper = new ObjectMapper();
		SecurityJacksonModules.registerModules(mapper);
		return mapper;
	}

	@Test(expected = IllegalArgumentException.class)
	public void nullKeyTest() {
		new CasAuthenticationToken(null, "user", PASSWORD, Collections.<GrantedAuthority>emptyList(),
				new User("user", PASSWORD, Collections.<GrantedAuthority>emptyList()), null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void blankKeyTest() {
		new CasAuthenticationToken("", "user", PASSWORD, Collections.<GrantedAuthority>emptyList(),
				new User("user", PASSWORD, Collections.<GrantedAuthority>emptyList()), null);
	}

	@Test
	public void serializeCasAuthenticationTest() throws JsonProcessingException, JSONException {
		CasAuthenticationToken token = createCasAuthenticationToken();
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(String.format(expectedJson, "\"" + PASSWORD + "\""), actualJson, true);
	}

	@Test
	public void serializeCasAuthenticationTestAfterEraseCredentialInvoked() throws JsonProcessingException, JSONException {
		CasAuthenticationToken token = createCasAuthenticationToken();
		token.eraseCredentials();
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(String.format(expectedJson, "null"), actualJson, true);
	}

	@Test
	public void deserializeCasAuthenticationTest() throws IOException, JSONException {
		CasAuthenticationToken token = buildObjectMapper().readValue(String.format(expectedJson, "\"" + PASSWORD + "\""), CasAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isInstanceOf(User.class);
		assertThat(((User) token.getPrincipal()).getUsername()).isEqualTo("username");
		assertThat(((User) token.getPrincipal()).getPassword()).isEqualTo(PASSWORD);
		assertThat(token.getUserDetails()).isNotNull().isInstanceOf(User.class);
		assertThat(token.getAssertion()).isNotNull().isInstanceOf(AssertionImpl.class);
		assertThat(token.getKeyHash()).isEqualTo(KEY.hashCode());
		assertThat(token.getUserDetails().getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(token.getAssertion().getAuthenticationDate()).isEqualTo(startDate);
		assertThat(token.getAssertion().getValidFromDate()).isEqualTo(startDate);
		assertThat(token.getAssertion().getValidUntilDate()).isEqualTo(endDate);
		assertThat(token.getAssertion().getPrincipal().getName()).isEqualTo("assertName");
		assertThat(token.getAssertion().getAttributes()).hasSize(0);
	}
}
