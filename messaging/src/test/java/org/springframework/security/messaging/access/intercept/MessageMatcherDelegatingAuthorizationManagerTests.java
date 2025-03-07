/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.messaging.access.intercept;

import java.util.Map;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.GenericMessage;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link MessageMatcherDelegatingAuthorizationManager}
 */
public final class MessageMatcherDelegatingAuthorizationManagerTests {

	@Test
	void checkWhenPermitAllThenPermits() {
		AuthorizationManager<Message<?>> authorizationManager = builder().anyMessage().permitAll().build();
		Message<?> message = new GenericMessage<>(new Object());
		assertThat(authorizationManager.check(mock(Supplier.class), message).isGranted()).isTrue();
	}

	@Test
	void checkWhenAnyMessageHasRoleThenRequires() {
		AuthorizationManager<Message<?>> authorizationManager = builder().anyMessage().hasRole("USER").build();
		Message<?> message = new GenericMessage<>(new Object());
		Authentication user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		assertThat(authorizationManager.check(() -> user, message).isGranted()).isTrue();
		Authentication admin = new TestingAuthenticationToken("user", "password", "ROLE_ADMIN");
		assertThat(authorizationManager.check(() -> admin, message).isGranted()).isFalse();
	}

	@Test
	void checkWhenSimpDestinationMatchesThenUses() {
		AuthorizationManager<Message<?>> authorizationManager = builder().destinationPathPatterns("/destination")
			.permitAll()
			.anyMessage()
			.denyAll()
			.build();
		MessageHeaders headers = new MessageHeaders(
				Map.of(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination"));
		Message<?> message = new GenericMessage<>(new Object(), headers);
		assertThat(authorizationManager.check(mock(Supplier.class), message).isGranted()).isTrue();
	}

	@Test
	void checkWhenNullDestinationHeaderMatchesThenUses() {
		AuthorizationManager<Message<?>> authorizationManager = builder().nullDestMatcher()
			.permitAll()
			.anyMessage()
			.denyAll()
			.build();
		Message<?> message = new GenericMessage<>(new Object());
		assertThat(authorizationManager.check(mock(Supplier.class), message).isGranted()).isTrue();
		MessageHeaders headers = new MessageHeaders(
				Map.of(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination"));
		message = new GenericMessage<>(new Object(), headers);
		assertThat(authorizationManager.check(mock(Supplier.class), message).isGranted()).isFalse();
	}

	@Test
	void checkWhenSimpTypeMatchesThenUses() {
		AuthorizationManager<Message<?>> authorizationManager = builder().simpTypeMatchers(SimpMessageType.CONNECT)
			.permitAll()
			.anyMessage()
			.denyAll()
			.build();
		MessageHeaders headers = new MessageHeaders(
				Map.of(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.CONNECT));
		Message<?> message = new GenericMessage<>(new Object(), headers);
		assertThat(authorizationManager.check(mock(Supplier.class), message).isGranted()).isTrue();
	}

	@Test
	void checkWhenMessageTypeAndPathPatternMatches() {
		AuthorizationManager<Message<?>> authorizationManager = builder()
			.simpTypeMessageDestinationPatterns("/destination")
			.permitAll()
			.simpTypeSubscribeDestinationPatterns("/destination")
			.denyAll()
			.anyMessage()
			.denyAll()
			.build();
		MessageHeaders headers = new MessageHeaders(Map.of(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER,
				SimpMessageType.MESSAGE, SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination"));
		Message<?> message = new GenericMessage<>(new Object(), headers);
		assertThat(authorizationManager.authorize(mock(Supplier.class), message).isGranted()).isTrue();
		MessageHeaders headers2 = new MessageHeaders(Map.of(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER,
				SimpMessageType.SUBSCRIBE, SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination"));
		Message<?> message2 = new GenericMessage<>(new Object(), headers2);
		assertThat(authorizationManager.check(mock(Supplier.class), message2).isGranted()).isFalse();
	}

	@Test
	void checkWhenMessageRouteAndPatternMismatch() {
		AuthorizationManager<Message<?>> authorizationManager = builder().messageRouteSeparator()
			.destinationPathPatterns("/destination.*")
			.permitAll()
			.anyMessage()
			.denyAll()
			.build();
		MessageHeaders headers = new MessageHeaders(
				Map.of(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination.sub.asdf"));
		Message<?> message = new GenericMessage<>(new Object(), headers);
		assertThat(authorizationManager.check(mock(Supplier.class), message).isGranted()).isFalse();
	}

	// gh-12540
	@Test
	void checkWhenSimpDestinationMatchesThenVariablesExtracted() {
		AuthorizationManager<Message<?>> authorizationManager = builder().destinationPathPatterns("/destination/{id}")
			.access(variable("id").isEqualTo("3"))
			.anyMessage()
			.denyAll()
			.build();
		MessageHeaders headers = new MessageHeaders(
				Map.of(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/3"));
		Message<?> message = new GenericMessage<>(new Object(), headers);
		assertThat(authorizationManager.check(mock(Supplier.class), message).isGranted()).isTrue();
	}

	@Test
	void checkWhenMessageRouteDestinationMatchesThenVariablesExtracted() {
		AuthorizationManager<Message<?>> authorizationManager = builder().messageRouteSeparator()
			.destinationPathPatterns("/destination.{id}")
			.access(variable("id").isEqualTo("3"))
			.anyMessage()
			.denyAll()
			.build();
		MessageHeaders headers = new MessageHeaders(
				Map.of(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination.3"));
		Message<?> message = new GenericMessage<>(new Object(), headers);
		assertThat(authorizationManager.check(mock(Supplier.class), message).isGranted()).isTrue();
	}

	private MessageMatcherDelegatingAuthorizationManager.Builder builder() {
		return MessageMatcherDelegatingAuthorizationManager.builder();
	}

	private Builder variable(String name) {
		return new Builder(name);

	}

	private record Builder(String name) {

		AuthorizationManager<MessageAuthorizationContext<?>> isEqualTo(String value) {
			return (authentication, object) -> {
				String extracted = object.getVariables().get(this.name);
				return new AuthorizationDecision(value.equals(extracted));
			};
		}

	}

}
