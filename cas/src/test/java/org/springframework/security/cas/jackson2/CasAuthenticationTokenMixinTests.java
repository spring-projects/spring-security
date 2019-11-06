/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.cas.jackson2;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jasig.cas.client.authentication.AttributePrincipalImpl;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.jackson2.SecurityJackson2Modules;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 * @since 4.2
 */
public class CasAuthenticationTokenMixinTests {

	private static final String KEY = "casKey";
	private static final String PASSWORD = "\"1234\"";
	private static final Date START_DATE = new Date();
	private static final Date END_DATE = new Date();

	public static final String AUTHORITY_JSON = "{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"authority\": \"ROLE_USER\"}";

	public static final String AUTHORITIES_SET_JSON = "[\"java.util.Collections$UnmodifiableSet\", [" + AUTHORITY_JSON + "]]";

	public static final String AUTHORITIES_ARRAYLIST_JSON = "[\"java.util.Collections$UnmodifiableRandomAccessList\", [" + AUTHORITY_JSON + "]]";

	// @formatter:off
	public static final String USER_JSON = "{"
		+ "\"@class\": \"org.springframework.security.core.userdetails.User\", "
		+ "\"username\": \"admin\","
		+ " \"password\": " + PASSWORD + ", "
		+ "\"accountNonExpired\": true, "
		+ "\"accountNonLocked\": true, "
		+ "\"credentialsNonExpired\": true, "
		+ "\"enabled\": true, "
		+ "\"authorities\": " + AUTHORITIES_SET_JSON
	+ "}";
	// @formatter:on

	private static final String CAS_TOKEN_JSON = "{"
		+ "\"@class\": \"org.springframework.security.cas.authentication.CasAuthenticationToken\", "
		+ "\"keyHash\": " + KEY.hashCode() + ","
		+ "\"principal\": " + USER_JSON + ", "
		+ "\"credentials\": " + PASSWORD + ", "
		+ "\"authorities\": " + AUTHORITIES_ARRAYLIST_JSON + ","
		+ "\"userDetails\": " + USER_JSON +","
		+ "\"authenticated\": true, "
		+ "\"details\": null,"
		+ "\"assertion\": {"
			+ "\"@class\": \"org.jasig.cas.client.validation.AssertionImpl\", "
			+ "\"principal\": {"
				+ "\"@class\": \"org.jasig.cas.client.authentication.AttributePrincipalImpl\", "
				+ "\"name\": \"assertName\", "
				+ "\"attributes\": {\"@class\": \"java.util.Collections$EmptyMap\"}, "
				+ "\"proxyGrantingTicket\": null, "
				+ "\"proxyRetriever\": null"
			+ "}, "
			+ "\"validFromDate\": [\"java.util.Date\", " + START_DATE.getTime() + "], "
			+ "\"validUntilDate\": [\"java.util.Date\", " + END_DATE.getTime() + "],"
			+ "\"authenticationDate\": [\"java.util.Date\", " + START_DATE.getTime() + "], "
			+ "\"attributes\": {\"@class\": \"java.util.Collections$EmptyMap\"}" +
		"}"
	+ "}";

	private static final String CAS_TOKEN_CLEARED_JSON = CAS_TOKEN_JSON.replaceFirst(PASSWORD, "null");

	protected ObjectMapper mapper;

	@Before
	public void setup() {
		mapper = new ObjectMapper();
		ClassLoader loader = getClass().getClassLoader();
		mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

	@Test
	public void serializeCasAuthenticationTest() throws JsonProcessingException, JSONException {
		CasAuthenticationToken token = createCasAuthenticationToken();
		String actualJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(CAS_TOKEN_JSON, actualJson, true);
	}

	@Test
	public void serializeCasAuthenticationTestAfterEraseCredentialInvoked() throws JsonProcessingException, JSONException {
		CasAuthenticationToken token = createCasAuthenticationToken();
		token.eraseCredentials();
		String actualJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(CAS_TOKEN_CLEARED_JSON, actualJson, true);
	}

	@Test
	public void deserializeCasAuthenticationTestAfterEraseCredentialInvoked() throws Exception {
		CasAuthenticationToken token = mapper.readValue(CAS_TOKEN_CLEARED_JSON, CasAuthenticationToken.class);
		assertThat(((UserDetails) token.getPrincipal()).getPassword()).isNull();
	}

	@Test
	public void deserializeCasAuthenticationTest() throws IOException {
		CasAuthenticationToken token = mapper.readValue(CAS_TOKEN_JSON, CasAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getPrincipal()).isNotNull().isInstanceOf(User.class);
		assertThat(((User) token.getPrincipal()).getUsername()).isEqualTo("admin");
		assertThat(((User) token.getPrincipal()).getPassword()).isEqualTo("1234");
		assertThat(token.getUserDetails()).isNotNull().isInstanceOf(User.class);
		assertThat(token.getAssertion()).isNotNull().isInstanceOf(AssertionImpl.class);
		assertThat(token.getKeyHash()).isEqualTo(KEY.hashCode());
		assertThat(token.getUserDetails().getAuthorities())
			.extracting(GrantedAuthority::getAuthority)
			.containsOnly("ROLE_USER");
		assertThat(token.getAssertion().getAuthenticationDate()).isEqualTo(START_DATE);
		assertThat(token.getAssertion().getValidFromDate()).isEqualTo(START_DATE);
		assertThat(token.getAssertion().getValidUntilDate()).isEqualTo(END_DATE);
		assertThat(token.getAssertion().getPrincipal().getName()).isEqualTo("assertName");
		assertThat(token.getAssertion().getAttributes()).hasSize(0);
	}

	private CasAuthenticationToken createCasAuthenticationToken() {
		User principal = new User("admin", "1234", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
		Collection<? extends GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
		Assertion assertion = new AssertionImpl(new AttributePrincipalImpl("assertName"), START_DATE, END_DATE, START_DATE, Collections.<String, Object>emptyMap());
		return new CasAuthenticationToken(KEY, principal, principal.getPassword(), authorities,
				new User("admin", "1234", authorities), assertion);
	}
}
