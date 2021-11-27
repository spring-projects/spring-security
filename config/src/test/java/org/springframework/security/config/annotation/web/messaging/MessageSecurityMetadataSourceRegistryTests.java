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

package org.springframework.security.config.annotation.web.messaging;

import java.util.Collection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.messaging.access.intercept.MessageSecurityMetadataSource;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.util.AntPathMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
public class MessageSecurityMetadataSourceRegistryTests {

	@Mock
	private MessageMatcher<Object> matcher;

	private MessageSecurityMetadataSourceRegistry messages;

	private Message<String> message;

	@BeforeEach
	public void setup() {
		this.messages = new MessageSecurityMetadataSourceRegistry();
		// @formatter:off
		this.message = MessageBuilder.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "location")
				.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE)
				.build();
		// @formatter:on
	}

	// See
	// https://github.com/spring-projects/spring-security/commit/3f30529039c76facf335d6ca69d18d8ae287f3f9#commitcomment-7412712
	// https://jira.spring.io/browse/SPR-11660
	@Test
	public void simpDestMatchersCustom() {
		// @formatter:off
		this.message = MessageBuilder.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "price.stock.1.2")
				.build();
		// @formatter:on
		this.messages.simpDestPathMatcher(new AntPathMatcher(".")).simpDestMatchers("price.stock.*").permitAll();
		assertThat(getAttribute()).isNull();
		// @formatter:off
		this.message = MessageBuilder.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "price.stock.1.2")
				.build();
		// @formatter:on
		this.messages.simpDestPathMatcher(new AntPathMatcher(".")).simpDestMatchers("price.stock.**").permitAll();
		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestMatchersCustomSetAfterMatchersDoesNotMatter() {
		// @formatter:off
		this.message = MessageBuilder.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "price.stock.1.2")
				.build();
		// @formatter:on
		this.messages.simpDestMatchers("price.stock.*").permitAll().simpDestPathMatcher(new AntPathMatcher("."));
		assertThat(getAttribute()).isNull();
		// @formatter:off
		this.message = MessageBuilder.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "price.stock.1.2")
				.build();
		// @formatter:on
		this.messages.simpDestMatchers("price.stock.**").permitAll().simpDestPathMatcher(new AntPathMatcher("."));
		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void pathMatcherNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.messages.simpDestPathMatcher(null));
	}

	@Test
	public void matchersFalse() {
		this.messages.matchers(this.matcher).permitAll();
		assertThat(getAttribute()).isNull();
	}

	@Test
	public void matchersTrue() {
		given(this.matcher.matches(this.message)).willReturn(true);
		this.messages.matchers(this.matcher).permitAll();
		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestMatchersExact() {
		this.messages.simpDestMatchers("location").permitAll();
		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestMatchersMulti() {
		// @formatter:off
		this.messages
				.simpDestMatchers("admin/**", "api/**").hasRole("ADMIN")
				.simpDestMatchers("location").permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestMatchersRole() {
		// @formatter:off
		this.messages
				.simpDestMatchers("admin/**", "location/**").hasRole("ADMIN")
				.anyMessage().denyAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("hasRole('ROLE_ADMIN')");
	}

	@Test
	public void simpDestMatchersAnyRole() {
		// @formatter:off
		this.messages
				.simpDestMatchers("admin/**", "location/**").hasAnyRole("ADMIN", "ROOT")
				.anyMessage().denyAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("hasAnyRole('ROLE_ADMIN','ROLE_ROOT')");
	}

	@Test
	public void simpDestMatchersAuthority() {
		// @formatter:off
		this.messages
				.simpDestMatchers("admin/**", "location/**").hasAuthority("ROLE_ADMIN")
				.anyMessage().fullyAuthenticated();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("hasAuthority('ROLE_ADMIN')");
	}

	@Test
	public void simpDestMatchersAccess() {
		String expected = "hasRole('ROLE_ADMIN') and fullyAuthenticated";
		this.messages.simpDestMatchers("admin/**", "location/**").access(expected).anyMessage().denyAll();
		assertThat(getAttribute()).isEqualTo(expected);
	}

	@Test
	public void simpDestMatchersAnyAuthority() {
		// @formatter:off
		this.messages
				.simpDestMatchers("admin/**", "location/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_ROOT")
				.anyMessage().denyAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("hasAnyAuthority('ROLE_ADMIN','ROLE_ROOT')");
	}

	@Test
	public void simpDestMatchersRememberMe() {
		// @formatter:off
		this.messages
				.simpDestMatchers("admin/**", "location/**").rememberMe()
				.anyMessage().denyAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("rememberMe");
	}

	@Test
	public void simpDestMatchersAnonymous() {
		// @formatter:off
		this.messages
				.simpDestMatchers("admin/**", "location/**").anonymous()
				.anyMessage().denyAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("anonymous");
	}

	@Test
	public void simpDestMatchersFullyAuthenticated() {
		// @formatter:off
		this.messages
				.simpDestMatchers("admin/**", "location/**").fullyAuthenticated()
				.anyMessage().denyAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("fullyAuthenticated");
	}

	@Test
	public void simpDestMatchersDenyAll() {
		// @formatter:off
		this.messages
				.simpDestMatchers("admin/**", "location/**").denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void simpDestMessageMatchersNotMatch() {
		// @formatter:off
		this.messages.
				simpMessageDestMatchers("admin/**").denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestMessageMatchersMatch() {
		// @formatter:off
		this.messages
				.simpMessageDestMatchers("location/**").denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void simpDestSubscribeMatchersNotMatch() {
		// @formatter:off
		this.messages
				.simpSubscribeDestMatchers("location/**").denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpDestSubscribeMatchersMatch() {
		// @formatter:off
		this.message = MessageBuilder.fromMessage(this.message)
				.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.SUBSCRIBE)
				.build();
		this.messages
				.simpSubscribeDestMatchers("location/**").denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void nullDestMatcherNotMatches() {
		// @formatter:off
		this.messages
				.nullDestMatcher().denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void nullDestMatcherMatch() {
		// @formatter:off
		this.message = MessageBuilder.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.CONNECT)
				.build();
		this.messages
				.nullDestMatcher().denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void simpTypeMatchersMatch() {
		// @formatter:off
		this.messages
				.simpTypeMatchers(SimpMessageType.MESSAGE).denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void simpTypeMatchersMatchMulti() {
		// @formatter:off
		this.messages
				.simpTypeMatchers(SimpMessageType.CONNECT, SimpMessageType.MESSAGE).denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("denyAll");
	}

	@Test
	public void simpTypeMatchersNotMatch() {
		// @formatter:off
		this.messages
				.simpTypeMatchers(SimpMessageType.CONNECT).denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	@Test
	public void simpTypeMatchersNotMatchMulti() {
		// @formatter:off
		this.messages
				.simpTypeMatchers(SimpMessageType.CONNECT, SimpMessageType.DISCONNECT).denyAll()
				.anyMessage().permitAll();
		// @formatter:on
		assertThat(getAttribute()).isEqualTo("permitAll");
	}

	private String getAttribute() {
		MessageSecurityMetadataSource source = this.messages.createMetadataSource();
		Collection<ConfigAttribute> attrs = source.getAttributes(this.message);
		if (attrs == null) {
			return null;
		}
		assertThat(attrs).hasSize(1);
		return attrs.iterator().next().toString();
	}

}
