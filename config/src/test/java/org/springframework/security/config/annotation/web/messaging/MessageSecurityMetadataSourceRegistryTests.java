/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.config.annotation.web.messaging;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.messaging.access.intercept.MessageSecurityMetadataSource;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class MessageSecurityMetadataSourceRegistryTests {
	@Mock
	private MessageMatcher<Object> matcher;

	private MessageSecurityMetadataSourceRegistry messages;

	private Message<String> message;

	@Before
	public void setup() {
		messages = new MessageSecurityMetadataSourceRegistry();
		message = MessageBuilder
				.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "location")
				.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER,
						SimpMessageType.MESSAGE).build();
	}

	// See
	// https://github.com/spring-projects/spring-security/commit/3f30529039c76facf335d6ca69d18d8ae287f3f9#commitcomment-7412712
	// https://jira.spring.io/browse/SPR-11660
	@Test
	public void simpDestMatchersCustom() {
		message = MessageBuilder
				.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER,
						"price.stock.1.2").build();
		messages.simpDestPathMatcher(new AntPathMatcher("."))
				.simpDestMatchers("price.stock.*").permitAll();

		assertThat(getAttribute()).isNull();

		message = MessageBuilder
				.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER,
						"price.stock.1.2").build();
		messages.simpDestPathMatcher(new AntPathMatcher("."))
				.simpDestMatchers("price.stock.**").permitAll();

		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestMatchersCustomSetAfterMatchersDoesNotMatter() {
		message = MessageBuilder
				.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER,
						"price.stock.1.2").build();
		messages.simpDestMatchers("price.stock.*").permitAll()
				.simpDestPathMatcher(new AntPathMatcher("."));

		assertThat(getAttribute()).isNull();

		message = MessageBuilder
				.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER,
						"price.stock.1.2").build();
		messages.simpDestMatchers("price.stock.**").permitAll()
				.simpDestPathMatcher(new AntPathMatcher("."));

		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test(expected = IllegalArgumentException.class)
	public void pathMatcherNull() {
		messages.simpDestPathMatcher(null);
	}

	@Test
	public void matchersFalse() {
		messages.matchers(matcher).permitAll();

		assertThat(getAttribute()).isNull();
	}

	@Test
	public void matchersTrue() {
		when(matcher.matches(message)).thenReturn(true);
		messages.matchers(matcher).permitAll();

		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestMatchersExact() {
		messages.simpDestMatchers("location").permitAll();

		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestMatchersMulti() {
		messages.simpDestMatchers("admin/**", "api/**").hasRole("ADMIN")
				.simpDestMatchers("location").permitAll();

		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestMatchersRole() {
		messages.simpDestMatchers("admin/**", "location/**").hasRole("ADMIN")
				.anyMessage().denyAll();

		assertThat(getAttribute()).isEqualTo("hasRole('ROLE_ADMIN')");
	}

	@Test
	public void simpDestMatchersAnyRole() {
		messages.simpDestMatchers("admin/**", "location/**").hasAnyRole("ADMIN", "ROOT")
				.anyMessage().denyAll();

		assertThat(getAttribute()).isEqualTo("hasAnyRole('ROLE_ADMIN','ROLE_ROOT')");
	}

	@Test
	public void simpDestMatchersAuthority() {
		messages.simpDestMatchers("admin/**", "location/**").hasAuthority("ROLE_ADMIN")
				.anyMessage().fullyAuthenticated();

		assertThat(getAttribute()).isEqualTo("hasAuthority('ROLE_ADMIN')");
	}

	@Test
	public void simpDestMatchersAccess() {
		String expected = "hasRole('ROLE_ADMIN') and fullyAuthenticated";
		messages.simpDestMatchers("admin/**", "location/**").access(expected)
				.anyMessage().denyAll();

		assertThat(getAttribute()).isEqualTo(expected);
	}

	@Test
	public void simpDestMatchersAnyAuthority() {
		messages.simpDestMatchers("admin/**", "location/**")
				.hasAnyAuthority("ROLE_ADMIN", "ROLE_ROOT").anyMessage().denyAll();

		assertThat(getAttribute()).isEqualTo("hasAnyAuthority('ROLE_ADMIN','ROLE_ROOT')");
	}

	@Test
	public void simpDestMatchersRememberMe() {
		messages.simpDestMatchers("admin/**", "location/**").rememberMe().anyMessage()
				.denyAll();

		assertThat(getAttribute()).isEqualTo("rememberMe");
	}

	@Test
	public void simpDestMatchersAnonymous() {
		messages.simpDestMatchers("admin/**", "location/**").anonymous().anyMessage()
				.denyAll();

		assertThat(getAttribute()).isEqualTo("anonymous");
	}

	@Test
	public void simpDestMatchersFullyAuthenticated() {
		messages.simpDestMatchers("admin/**", "location/**").fullyAuthenticated()
				.anyMessage().denyAll();

		assertThat(getAttribute()).isEqualTo("fullyAuthenticated");
	}

	@Test
	public void simpDestMatchersDenyAll() {
		messages.simpDestMatchers("admin/**", "location/**").denyAll().anyMessage()
				.permitAll();

		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void simpDestMessageMatchersNotMatch() {
		messages.simpMessageDestMatchers("admin/**").denyAll().anyMessage().permitAll();

		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestMessageMatchersMatch() {
		messages.simpMessageDestMatchers("location/**").denyAll().anyMessage()
				.permitAll();

		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void simpDestSubscribeMatchersNotMatch() {
		messages.simpSubscribeDestMatchers("location/**").denyAll().anyMessage()
				.permitAll();

		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestSubscribeMatchersMatch() {
		message = MessageBuilder
				.fromMessage(message)
				.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER,
						SimpMessageType.SUBSCRIBE).build();

		messages.simpSubscribeDestMatchers("location/**").denyAll().anyMessage()
				.permitAll();

		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void nullDestMatcherNotMatches() {
		messages.nullDestMatcher().denyAll().anyMessage().permitAll();

		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void nullDestMatcherMatch() {
		message = MessageBuilder
				.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER,
						SimpMessageType.CONNECT).build();

		messages.nullDestMatcher().denyAll().anyMessage().permitAll();

		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void simpTypeMatchersMatch() {
		messages.simpTypeMatchers(SimpMessageType.MESSAGE).denyAll().anyMessage()
				.permitAll();

		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void simpTypeMatchersMatchMulti() {
		messages.simpTypeMatchers(SimpMessageType.CONNECT, SimpMessageType.MESSAGE)
				.denyAll().anyMessage().permitAll();

		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void simpTypeMatchersNotMatch() {
		messages.simpTypeMatchers(SimpMessageType.CONNECT).denyAll().anyMessage()
				.permitAll();

		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpTypeMatchersNotMatchMulti() {
		messages.simpTypeMatchers(SimpMessageType.CONNECT, SimpMessageType.DISCONNECT)
				.denyAll().anyMessage().permitAll();

		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	private String getAttribute() {
		MessageSecurityMetadataSource source = messages.createMetadataSource();
		Collection<ConfigAttribute> attrs = source.getAttributes(message);
		if (attrs == null) {
			return null;
		}
		assertThat(attrs.size()).isEqualTo(1);
		return attrs.iterator().next().toString();
	}
}