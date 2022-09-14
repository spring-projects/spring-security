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
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.MethodParameter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageDeliveryException;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.support.AbstractMessageChannel;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.GenericMessage;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.web.messaging.MessageSecurityMetadataSourceRegistry;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor;
import org.springframework.security.messaging.access.intercept.MessageAuthorizationContext;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.security.messaging.web.csrf.CsrfChannelInterceptor;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.stereotype.Controller;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.HttpRequestHandler;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.server.HandshakeFailureException;
import org.springframework.web.socket.server.HandshakeHandler;
import org.springframework.web.socket.server.support.HttpSessionHandshakeInterceptor;
import org.springframework.web.socket.sockjs.transport.handler.SockJsWebSocketHandler;
import org.springframework.web.socket.sockjs.transport.session.WebSocketServerSockJsSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;

public class WebSocketMessageBrokerSecurityConfigurationTests {

	AnnotationConfigWebApplicationContext context;

	Authentication messageUser;

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
	public void simpleRegistryMappings() {
		loadConfig(SockJsSecurityConfig.class);
		clientInboundChannel().send(message("/permitAll"));
		assertThatExceptionOfType(MessageDeliveryException.class)
				.isThrownBy(() -> clientInboundChannel().send(message("/denyAll")))
				.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void annonymousSupported() {
		loadConfig(SockJsSecurityConfig.class);
		this.messageUser = null;
		clientInboundChannel().send(message("/permitAll"));
	}

	// gh-3797
	@Test
	public void beanResolver() {
		loadConfig(SockJsSecurityConfig.class);
		this.messageUser = null;
		clientInboundChannel().send(message("/beanResolver"));
	}

	@Test
	public void addsAuthenticationPrincipalResolver() {
		loadConfig(SockJsSecurityConfig.class);
		MessageChannel messageChannel = clientInboundChannel();
		Message<String> message = message("/permitAll/authentication");
		messageChannel.send(message);
		assertThat(this.context.getBean(MyController.class).authenticationPrincipal)
				.isEqualTo((String) this.messageUser.getPrincipal());
	}

	@Test
	public void addsAuthenticationPrincipalResolverWhenNoAuthorization() {
		loadConfig(NoInboundSecurityConfig.class);
		MessageChannel messageChannel = clientInboundChannel();
		Message<String> message = message("/permitAll/authentication");
		messageChannel.send(message);
		assertThat(this.context.getBean(MyController.class).authenticationPrincipal)
				.isEqualTo((String) this.messageUser.getPrincipal());
	}

	@Test
	public void addsCsrfProtectionWhenNoAuthorization() {
		loadConfig(NoInboundSecurityConfig.class);
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		Message<?> message = message(headers, "/authentication");
		MessageChannel messageChannel = clientInboundChannel();
		assertThatExceptionOfType(MessageDeliveryException.class).isThrownBy(() -> messageChannel.send(message))
				.withCauseInstanceOf(MissingCsrfTokenException.class);
	}

	@Test
	public void csrfProtectionForConnect() {
		loadConfig(SockJsSecurityConfig.class);
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		Message<?> message = message(headers, "/authentication");
		MessageChannel messageChannel = clientInboundChannel();
		assertThatExceptionOfType(MessageDeliveryException.class).isThrownBy(() -> messageChannel.send(message))
				.withCauseInstanceOf(MissingCsrfTokenException.class);
	}

	@Test
	@Disabled // to be added back in with the introduction of DSL support
	public void csrfProtectionDisabledForConnect() {
		loadConfig(CsrfDisabledSockJsSecurityConfig.class);
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		Message<?> message = message(headers, "/permitAll/connect");
		MessageChannel messageChannel = clientInboundChannel();
		messageChannel.send(message);
	}

	@Test
	public void csrfProtectionDefinedByBean() {
		loadConfig(SockJsProxylessSecurityConfig.class);
		MessageChannel messageChannel = clientInboundChannel();
		Stream<Class<? extends ChannelInterceptor>> interceptors = ((AbstractMessageChannel) messageChannel)
				.getInterceptors().stream().map(ChannelInterceptor::getClass);
		assertThat(interceptors).contains(CsrfChannelInterceptor.class);
	}

	@Test
	public void messagesConnectUseCsrfTokenHandshakeInterceptor() throws Exception {
		loadConfig(SockJsSecurityConfig.class);
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		Message<?> message = message(headers, "/authentication");
		MockHttpServletRequest request = sockjsHttpRequest("/chat");
		HttpRequestHandler handler = handler(request);
		handler.handleRequest(request, new MockHttpServletResponse());
		assertHandshake(request);
	}

	@Test
	public void messagesConnectUseCsrfTokenHandshakeInterceptorMultipleMappings() throws Exception {
		loadConfig(SockJsSecurityConfig.class);
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		Message<?> message = message(headers, "/authentication");
		MockHttpServletRequest request = sockjsHttpRequest("/other");
		HttpRequestHandler handler = handler(request);
		handler.handleRequest(request, new MockHttpServletResponse());
		assertHandshake(request);
	}

	@Test
	public void messagesConnectWebSocketUseCsrfTokenHandshakeInterceptor() throws Exception {
		loadConfig(WebSocketSecurityConfig.class);
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		Message<?> message = message(headers, "/authentication");
		MockHttpServletRequest request = websocketHttpRequest("/websocket");
		HttpRequestHandler handler = handler(request);
		handler.handleRequest(request, new MockHttpServletResponse());
		assertHandshake(request);
	}

	@Test
	public void messagesContextWebSocketUseSecurityContextHolderStrategy() {
		loadConfig(WebSocketSecurityConfig.class, SecurityContextChangedListenerConfig.class);
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		headers.setNativeHeader(this.token.getHeaderName(), this.token.getToken());
		Message<?> message = message(headers, "/authenticated");
		headers.getSessionAttributes().put(CsrfToken.class.getName(), this.token);
		MessageChannel messageChannel = clientInboundChannel();
		messageChannel.send(message);
		verify(this.context.getBean(SecurityContextHolderStrategy.class), atLeastOnce()).getContext();
	}

	@Test
	public void msmsRegistryCustomPatternMatcher() {
		loadConfig(MsmsRegistryCustomPatternMatcherConfig.class);
		clientInboundChannel().send(message("/app/a.b"));
		assertThatExceptionOfType(MessageDeliveryException.class)
				.isThrownBy(() -> clientInboundChannel().send(message("/app/a.b.c")))
				.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void overrideMsmsRegistryCustomPatternMatcher() {
		loadConfig(OverrideMsmsRegistryCustomPatternMatcherConfig.class);
		clientInboundChannel().send(message("/app/a/b"));
		assertThatExceptionOfType(MessageDeliveryException.class)
				.isThrownBy(() -> clientInboundChannel().send(message("/app/a/b/c")))
				.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void defaultPatternMatcher() {
		loadConfig(DefaultPatternMatcherConfig.class);
		clientInboundChannel().send(message("/app/a/b"));
		assertThatExceptionOfType(MessageDeliveryException.class)
				.isThrownBy(() -> clientInboundChannel().send(message("/app/a/b/c")))
				.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void customExpression() {
		loadConfig(CustomExpressionConfig.class);
		clientInboundChannel().send(message("/denyRob"));
		this.messageUser = new TestingAuthenticationToken("rob", "password", "ROLE_USER");
		assertThatExceptionOfType(MessageDeliveryException.class)
				.isThrownBy(() -> clientInboundChannel().send(message("/denyRob")))
				.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void channelSecurityInterceptorUsesMetadataSourceBeanWhenProxyingDisabled() {
		loadConfig(SockJsProxylessSecurityConfig.class);
		AbstractMessageChannel messageChannel = clientInboundChannel();
		AuthorizationManager<Message<?>> authorizationManager = this.context.getBean(AuthorizationManager.class);
		for (ChannelInterceptor interceptor : messageChannel.getInterceptors()) {
			if (interceptor instanceof AuthorizationChannelInterceptor) {
				assertThat(ReflectionTestUtils.getField(interceptor, "preSendAuthorizationManager"))
						.isSameAs(authorizationManager);
				return;
			}
		}
		fail("did not find AuthorizationChannelInterceptor");
	}

	@Test
	public void securityContextChannelInterceptorDefinedByBean() {
		loadConfig(SockJsProxylessSecurityConfig.class);
		MessageChannel messageChannel = clientInboundChannel();
		Stream<Class<? extends ChannelInterceptor>> interceptors = ((AbstractMessageChannel) messageChannel)
				.getInterceptors().stream().map(ChannelInterceptor::getClass);
		assertThat(interceptors).contains(SecurityContextChannelInterceptor.class);
	}

	@Test
	public void inboundChannelSecurityDefinedByBean() {
		loadConfig(SockJsProxylessSecurityConfig.class);
		MessageChannel messageChannel = clientInboundChannel();
		Stream<Class<? extends ChannelInterceptor>> interceptors = ((AbstractMessageChannel) messageChannel)
				.getInterceptors().stream().map(ChannelInterceptor::getClass);
		assertThat(interceptors).contains(AuthorizationChannelInterceptor.class);
	}

	@Test
	public void sendMessageWhenFullyAuthenticatedConfiguredAndRememberMeTokenThenAccessDeniedException() {
		loadConfig(WebSocketSecurityConfig.class);
		this.messageUser = new RememberMeAuthenticationToken("key", "user",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		assertThatExceptionOfType(MessageDeliveryException.class)
				.isThrownBy(() -> clientInboundChannel().send(message("/fullyAuthenticated")))
				.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendMessageWhenFullyAuthenticatedConfiguredAndUserThenPasses() {
		loadConfig(WebSocketSecurityConfig.class);
		clientInboundChannel().send(message("/fullyAuthenticated"));
	}

	@Test
	public void sendMessageWhenRememberMeConfiguredAndNoUserThenAccessDeniedException() {
		loadConfig(WebSocketSecurityConfig.class);
		this.messageUser = null;
		assertThatExceptionOfType(MessageDeliveryException.class)
				.isThrownBy(() -> clientInboundChannel().send(message("/rememberMe")))
				.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendMessageWhenRememberMeConfiguredAndRememberMeTokenThenPasses() {
		loadConfig(WebSocketSecurityConfig.class);
		this.messageUser = new RememberMeAuthenticationToken("key", "user",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		clientInboundChannel().send(message("/rememberMe"));
	}

	@Test
	public void sendMessageWhenAnonymousConfiguredAndAnonymousUserThenPasses() {
		loadConfig(WebSocketSecurityConfig.class);
		this.messageUser = new AnonymousAuthenticationToken("key", "user",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		clientInboundChannel().send(message("/anonymous"));
	}

	@Test
	public void sendMessageWhenAnonymousConfiguredAndLoggedInUserThenAccessDeniedException() {
		loadConfig(WebSocketSecurityConfig.class);
		assertThatExceptionOfType(MessageDeliveryException.class)
				.isThrownBy(() -> clientInboundChannel().send(message("/anonymous")))
				.withCauseInstanceOf(AccessDeniedException.class);

	}

	private void assertHandshake(HttpServletRequest request) {
		TestHandshakeHandler handshakeHandler = this.context.getBean(TestHandshakeHandler.class);
		assertThat(handshakeHandler.attributes.get(CsrfToken.class.getName())).isSameAs(this.token);
		assertThat(handshakeHandler.attributes.get(this.sessionAttr))
				.isEqualTo(request.getSession().getAttribute(this.sessionAttr));
	}

	private HttpRequestHandler handler(HttpServletRequest request) throws Exception {
		HandlerMapping handlerMapping = this.context.getBean(HandlerMapping.class);
		return (HttpRequestHandler) handlerMapping.getHandler(request).getHandler();
	}

	private MockHttpServletRequest websocketHttpRequest(String mapping) {
		MockHttpServletRequest request = sockjsHttpRequest(mapping);
		request.setRequestURI(mapping);
		return request;
	}

	private MockHttpServletRequest sockjsHttpRequest(String mapping) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setMethod("GET");
		request.setAttribute(HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE, "/289/tpyx6mde/websocket");
		request.setRequestURI(mapping + "/289/tpyx6mde/websocket");
		request.getSession().setAttribute(this.sessionAttr, "sessionValue");
		request.setAttribute(CsrfToken.class.getName(), this.token);
		return request;
	}

	private Message<String> message(String destination) {
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create();
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

	private <T extends MessageChannel> T clientInboundChannel() {
		return (T) this.context.getBean("clientInboundChannel", MessageChannel.class);
	}

	private void loadConfig(Class<?>... configs) {
		this.context = new AnnotationConfigWebApplicationContext();
		this.context.register(configs);
		this.context.setServletConfig(new MockServletConfig());
		this.context.refresh();
	}

	@Configuration
	@EnableWebSocketMessageBroker
	@EnableWebSocketSecurity
	@Import(SyncExecutorConfig.class)
	static class MsmsRegistryCustomPatternMatcherConfig implements WebSocketMessageBrokerConfigurer {

		// @formatter:off
		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry
				.addEndpoint("/other")
				.setHandshakeHandler(testHandshakeHandler());
		}
		// @formatter:on

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.setPathMatcher(new AntPathMatcher("."));
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/app");
		}

		// @formatter:off
		@Bean
		AuthorizationManager<Message<?>> authorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
			messages
					.simpDestMatchers("/app/a.*").permitAll()
					.anyMessage().denyAll();

			return messages.build();
		}
		// @formatter:on

		@Bean
		TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Configuration
	@EnableWebSocketMessageBroker
	@EnableWebSocketSecurity
	@Import(SyncExecutorConfig.class)
	static class OverrideMsmsRegistryCustomPatternMatcherConfig implements WebSocketMessageBrokerConfigurer {

		// @formatter:off
		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry
				.addEndpoint("/other")
				.setHandshakeHandler(testHandshakeHandler());
		}
		// @formatter:on

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.setPathMatcher(new AntPathMatcher("."));
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/app");
		}

		// @formatter:off
		@Bean
		AuthorizationManager<Message<?>> authorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
			messages
					.simpDestPathMatcher(new AntPathMatcher())
					.simpDestMatchers("/app/a/*").permitAll()
					.anyMessage().denyAll();
			return messages.build();
		}
		// @formatter:on

		@Bean
		TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Configuration
	@EnableWebSocketMessageBroker
	@EnableWebSocketSecurity
	@Import(SyncExecutorConfig.class)
	static class DefaultPatternMatcherConfig implements WebSocketMessageBrokerConfigurer {

		// @formatter:off
		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry
				.addEndpoint("/other")
				.setHandshakeHandler(testHandshakeHandler());
		}
		// @formatter:on

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/app");
		}

		// @formatter:off
		@Bean
		AuthorizationManager<Message<?>> authorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
			messages
					.simpDestMatchers("/app/a/*").permitAll()
					.anyMessage().denyAll();

			return messages.build();
		}
		// @formatter:on

		@Bean
		TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Configuration
	@EnableWebSocketMessageBroker
	@EnableWebSocketSecurity
	@Import(SyncExecutorConfig.class)
	static class CustomExpressionConfig implements WebSocketMessageBrokerConfigurer {

		// @formatter:off
		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry
				.addEndpoint("/other")
				.setHandshakeHandler(testHandshakeHandler());
		}
		// @formatter:on

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/app");
		}

		@Bean
		AuthorizationManager<Message<Object>> authorizationManager() {
			return (authentication, message) -> {
				Authentication auth = authentication.get();
				return new AuthorizationDecision(auth != null && !"rob".equals(auth.getName()));
			};
		}

		@Bean
		TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Controller
	static class MyController {

		String authenticationPrincipal;

		MyCustomArgument myCustomArgument;

		@MessageMapping("/authentication")
		void authentication(@AuthenticationPrincipal String un) {
			this.authenticationPrincipal = un;
		}

		@MessageMapping("/myCustom")
		void myCustom(MyCustomArgument myCustomArgument) {
			this.myCustomArgument = myCustomArgument;
		}

	}

	static class MyCustomArgument {

		MyCustomArgument(String notDefaultConstr) {
		}

	}

	static class MyCustomArgumentResolver implements HandlerMethodArgumentResolver {

		@Override
		public boolean supportsParameter(MethodParameter parameter) {
			return parameter.getParameterType().isAssignableFrom(MyCustomArgument.class);
		}

		@Override
		public Object resolveArgument(MethodParameter parameter, Message<?> message) {
			return new MyCustomArgument("");
		}

	}

	static class TestHandshakeHandler implements HandshakeHandler {

		Map<String, Object> attributes;

		@Override
		public boolean doHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler,
				Map<String, Object> attributes) throws HandshakeFailureException {
			this.attributes = attributes;
			if (wsHandler instanceof SockJsWebSocketHandler) {
				// work around SPR-12716
				SockJsWebSocketHandler sockJs = (SockJsWebSocketHandler) wsHandler;
				WebSocketServerSockJsSession session = (WebSocketServerSockJsSession) ReflectionTestUtils
						.getField(sockJs, "sockJsSession");
				this.attributes = session.getAttributes();
			}
			return true;
		}

	}

	@Configuration
	@EnableWebSocketSecurity
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class SockJsSecurityConfig implements WebSocketMessageBrokerConfigurer {

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			// @formatter:off
			registry.addEndpoint("/other").setHandshakeHandler(testHandshakeHandler())
					.withSockJS().setInterceptors(new HttpSessionHandshakeInterceptor());
			registry.addEndpoint("/chat").setHandshakeHandler(testHandshakeHandler())
					.withSockJS().setInterceptors(new HttpSessionHandshakeInterceptor());
			// @formatter:on
		}

		// @formatter:off
		@Bean
		AuthorizationManager<Message<?>> authorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages,
				SecurityCheck security) {
			AuthorizationManager<MessageAuthorizationContext<?>> beanResolver =
					(authentication, context) -> new AuthorizationDecision(security.check());
			messages
				.simpDestMatchers("/permitAll/**").permitAll()
				.simpDestMatchers("/beanResolver/**").access(beanResolver)
				.anyMessage().denyAll();
			return messages.build();
		}
		// @formatter:on

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/permitAll", "/denyAll");
		}

		@Bean
		MyController myController() {
			return new MyController();
		}

		@Bean
		TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

		@Bean
		SecurityCheck security() {
			return new SecurityCheck();
		}

		static class SecurityCheck {

			private boolean check;

			boolean check() {
				this.check = !this.check;
				return this.check;
			}

		}

	}

	@Configuration
	@EnableWebSocketSecurity
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class NoInboundSecurityConfig implements WebSocketMessageBrokerConfigurer {

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			// @formatter:off
			registry.addEndpoint("/other")
					.withSockJS().setInterceptors(new HttpSessionHandshakeInterceptor());
			registry.addEndpoint("/chat")
					.withSockJS().setInterceptors(new HttpSessionHandshakeInterceptor());
			// @formatter:on
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
	@Import(SockJsSecurityConfig.class)
	static class CsrfDisabledSockJsSecurityConfig {

		@Bean
		Consumer<List<ChannelInterceptor>> channelInterceptorCustomizer() {
			return (interceptors) -> interceptors.remove(1);
		}

	}

	@Configuration
	@EnableWebSocketSecurity
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class WebSocketSecurityConfig implements WebSocketMessageBrokerConfigurer {

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			// @formatter:off
			registry.addEndpoint("/websocket")
					.setHandshakeHandler(testHandshakeHandler())
					.addInterceptors(new HttpSessionHandshakeInterceptor());
			// @formatter:on
		}

		@Bean
		AuthorizationManager<Message<?>> authorizationManager(
				MessageMatcherDelegatingAuthorizationManager.Builder messages) {
			// @formatter:off
			messages
				.simpDestMatchers("/permitAll/**").permitAll()
				.simpDestMatchers("/authenticated/**").authenticated()
				.simpDestMatchers("/fullyAuthenticated/**").fullyAuthenticated()
				.simpDestMatchers("/rememberMe/**").rememberMe()
				.simpDestMatchers("/anonymous/**").anonymous()
				.anyMessage().denyAll();
			// @formatter:on
			return messages.build();
		}

		@Bean
		TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Configuration
	@EnableWebSocketSecurity
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class UsingLegacyConfigurerConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			// @formatter:off
			registry.addEndpoint("/websocket")
					.setHandshakeHandler(testHandshakeHandler())
					.addInterceptors(new HttpSessionHandshakeInterceptor());
			// @formatter:on
		}

		@Override
		public void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
			// @formatter:off
			messages
					.simpDestMatchers("/permitAll/**").permitAll()
					.anyMessage().denyAll();
			// @formatter:on
		}

		@Bean
		TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSocketSecurity
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class SockJsProxylessSecurityConfig implements WebSocketMessageBrokerConfigurer {

		private ApplicationContext context;

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			// @formatter:off
			registry.addEndpoint("/chat")
					.setHandshakeHandler(this.context.getBean(TestHandshakeHandler.class))
					.withSockJS().setInterceptors(new HttpSessionHandshakeInterceptor());
			// @formatter:on
		}

		@Autowired
		void setContext(ApplicationContext context) {
			this.context = context;
		}

		// @formatter:off
		@Bean
		AuthorizationManager<Message<?>> authorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
			messages
					.anyMessage().denyAll();
			return messages.build();
		}
		// @formatter:on

		@Bean
		TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
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
