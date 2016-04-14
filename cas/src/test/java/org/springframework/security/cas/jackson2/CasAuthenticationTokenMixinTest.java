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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.PropertyAccessor;
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
import org.springframework.security.jackson2.SimpleGrantedAuthorityMixin;
import org.springframework.security.jackson2.UnmodifiableSetMixin;
import org.springframework.security.jackson2.UserMixin;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Jitendra Singh
 */
@RunWith(MockitoJUnitRunner.class)
public class CasAuthenticationTokenMixinTest {

	ObjectMapper buildObjectMapper() {
		ObjectMapper mapper = new ObjectMapper()
				.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
		mapper.setVisibilityChecker(mapper.getVisibilityChecker().withVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY));
		mapper.addMixIn(CasAuthenticationToken.class, CasAuthenticationTokenMixin.class)
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
				.addMixIn(Collections.unmodifiableSet(Collections.EMPTY_SET).getClass(), UnmodifiableSetMixin.class)
				.addMixIn(User.class, UserMixin.class)
				.addMixIn(AssertionImpl.class, AssertionImplMixin.class)
				.addMixIn(AttributePrincipalImpl.class, AttributePrincipalImplMixin.class);
		return mapper;
	}

	@Test(expected = IllegalArgumentException.class)
	public void nullKeyTest() {
		new CasAuthenticationToken(null, "user", "pass", Collections.<GrantedAuthority>emptyList(),
				new User("user", "pass", Collections.<GrantedAuthority>emptyList()), null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void blankKeyTest() {
		new CasAuthenticationToken("", "user", "pass", Collections.<GrantedAuthority>emptyList(),
				new User("user", "pass", Collections.<GrantedAuthority>emptyList()), null);
	}

	@Test
	public void serializeCasAuthenticationTest() throws JsonProcessingException, JSONException {
		String key = "casKey";
		Date startDate = new Date();
		Date endDate = new Date();
		Collection<? extends GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
		Assertion assertion = new AssertionImpl(new AttributePrincipalImpl("assertName"), startDate, endDate, startDate, Collections.<String, Object>emptyMap());
		CasAuthenticationToken token = new CasAuthenticationToken(key, "user", "pass", authorities,
				new User("user", "pass", authorities), assertion);

		String expectedJson = "{\"@class\": \"org.springframework.security.cas.authentication.CasAuthenticationToken\", \"keyHash\": "+key.hashCode()+"," +
				"\"principal\": \"user\", \"credentials\": \"pass\", \"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]," +
				"\"userDetails\": {\"@class\": \"org.springframework.security.core.userdetails.User\",\"username\": \"user\", \"password\": \"pass\", \"enabled\": true, \"accountNonExpired\": true, \"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}," +
				"\"authenticated\": true, \"details\": null, \"name\": \"user\"," +
				"\"assertion\": {" +
					"\"@class\": \"org.jasig.cas.client.validation.AssertionImpl\", \"principal\": {\"@class\": \"org.jasig.cas.client.authentication.AttributePrincipalImpl\", \"name\": \"assertName\", \"attributes\": {\"@class\": \"java.util.Collections$EmptyMap\"}, \"proxyGrantingTicket\": null, \"proxyRetriever\": null}, " +
					"\"validFromDate\": [\"java.util.Date\", "+startDate.getTime()+"], \"validUntilDate\": [\"java.util.Date\", "+endDate.getTime()+"]," +
					"\"authenticationDate\": [\"java.util.Date\", "+startDate.getTime()+"], \"attributes\": {\"@class\": \"java.util.Collections$EmptyMap\"}" +
				"}}";
		String actualJson = buildObjectMapper().writeValueAsString(token);
		JSONAssert.assertEquals(expectedJson, actualJson, true);
	}

	@Test
	public void deserializeCasAuthenticationTest() throws IOException, JSONException {
		String key = "casKey";
		Date startDate = new Date();
		Date endDate = new Date();

		String expectedJson = "{\"@class\": \"org.springframework.security.cas.authentication.CasAuthenticationToken\", \"keyHash\": "+key.hashCode()+"," +
				"\"principal\": \"user\", \"credentials\": \"pass\", \"authorities\": [\"java.util.ArrayList\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]," +
				"\"userDetails\": {\"@class\": \"org.springframework.security.core.userdetails.User\",\"username\": \"user\", \"password\": \"pass\", \"enabled\": true, \"accountNonExpired\": true, \"accountNonLocked\": true, \"credentialsNonExpired\": true, \"authorities\": [\"java.util.Collections$UnmodifiableSet\", [{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}]]}," +
				"\"authenticated\": true, \"details\": null, \"name\": \"user\"," +
				"\"assertion\": {" +
				"\"@class\": \"org.jasig.cas.client.validation.AssertionImpl\", \"principal\": {\"@class\": \"org.jasig.cas.client.authentication.AttributePrincipalImpl\", \"name\": \"assertName\", \"attributes\": {\"@class\": \"java.util.Collections$EmptyMap\"}, \"proxyGrantingTicket\": null, \"proxyRetriever\": null}, " +
				"\"validFromDate\": [\"java.util.Date\", "+startDate.getTime()+"], \"validUntilDate\": [\"java.util.Date\", "+endDate.getTime()+"]," +
				"\"authenticationDate\": [\"java.util.Date\", "+startDate.getTime()+"], \"attributes\": {\"@class\": \"java.util.Collections$EmptyMap\"}" +
				"}}";
		CasAuthenticationToken token = buildObjectMapper().readValue(expectedJson, CasAuthenticationToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getUserDetails()).isNotNull().isInstanceOf(User.class);
		assertThat(token.getAssertion()).isNotNull().isInstanceOf(AssertionImpl.class);
		assertThat(token.getKeyHash()).isEqualTo(key.hashCode());
		assertThat(token.getUserDetails().getAuthorities()).hasSize(1).contains(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(token.getAssertion().getAuthenticationDate()).isEqualTo(startDate);
		assertThat(token.getAssertion().getValidFromDate()).isEqualTo(startDate);
		assertThat(token.getAssertion().getValidUntilDate()).isEqualTo(endDate);
		assertThat(token.getAssertion().getPrincipal().getName()).isEqualTo("assertName");
		assertThat(token.getAssertion().getAttributes()).hasSize(0);
	}
}
