/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.socket;

import java.util.HashMap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageDeliveryException;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.support.GenericMessage;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class WebSocketMessageBrokerSecurityConfigurationDocTests {

	AnnotationConfigWebApplicationContext context;

	TestingAuthenticationToken messageUser;

	CsrfToken token;

	String sessionAttr;

	@BeforeEach
	public void setup() {
		this.token = new DefaultCsrfToken("header", "param", "token");
		this.sessionAttr = "sessionAttr";
		this.messageUser = new TestingAuthenticationToken("user", "pass", "ROLE_USER");
	}

	@AfterEach
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void securityMappings() {
		loadConfig(WebSocketSecurityConfig.class);
		clientInboundChannel().send(message("/user/queue/errors", SimpMessageType.SUBSCRIBE));
		assertThatExceptionOfType(MessageDeliveryException.class)
				.isThrownBy(() -> clientInboundChannel().send(message("/denyAll", SimpMessageType.MESSAGE)))
				.withCauseInstanceOf(AccessDeniedException.class);
	}

	private void loadConfig(Class<?>... configs) {
		this.context = new AnnotationConfigWebApplicationContext();
		this.context.register(configs);
		this.context.register(WebSocketConfig.class, SyncExecutorConfig.class);
		this.context.setServletConfig(new MockServletConfig());
		this.context.refresh();
	}

	private MessageChannel clientInboundChannel() {
		return this.context.getBean("clientInboundChannel", MessageChannel.class);
	}

	private Message<String> message(String destination, SimpMessageType type) {
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(type);
		return message(headers, destination);
	}

	private Message<String> message(SimpMessageHeaderAccessor headers, String destination) {
		headers.setSessionId("123");
		headers.setSessionAttributes(new HashMap<>());
		if (destination != null) {
			headers.setDestination(destination);
		}
		if (this.messageUser != null) {
			headers.setUser(this.messageUser);
		}
		return new GenericMessage<>("hi", headers.getMessageHeaders());
	}

	@Controller
	static class MyController {

		@MessageMapping("/authentication")
		void authentication(@AuthenticationPrincipal String un) {
			// ... do something ...
		}

	}

	@Configuration
	@EnableWebSocketSecurity
	static class WebSocketSecurityConfig {

		@Bean
		AuthorizationManager<Message<?>> authorizationManager(
				MessageMatcherDelegatingAuthorizationManager.Builder messages) {
			messages.nullDestMatcher().authenticated()
					// <1>
					.simpSubscribeDestMatchers("/user/queue/errors").permitAll()
					// <2>
					.simpDestMatchers("/app/**").hasRole("USER")
					// <3>
					.simpSubscribeDestMatchers("/user/**", "/topic/friends/*").hasRole("USER") // <4>
					.simpTypeMatchers(SimpMessageType.MESSAGE, SimpMessageType.SUBSCRIBE).denyAll() // <5>
					.anyMessage().denyAll(); // <6>
			return messages.build();
		}

	}

	@Configuration
	@EnableWebSocketMessageBroker
	static class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry.addEndpoint("/chat").withSockJS();
		}

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/permitAll", "/denyAll");
		}

		@Bean
		MyController myController() {
			return new MyController();
		}

	}

	@Configuration
	static class SyncExecutorConfig {

		@Bean
		static SyncExecutorSubscribableChannelPostProcessor postProcessor() {
			return new SyncExecutorSubscribableChannelPostProcessor();
		}

	}

}
