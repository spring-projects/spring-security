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

package org.springframework.security.config.annotation.web.socket;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

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
import org.springframework.messaging.support.GenericMessage;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.messaging.MessageSecurityMetadataSourceRegistry;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.messaging.access.expression.DefaultMessageSecurityExpressionHandler;
import org.springframework.security.messaging.access.expression.MessageSecurityExpressionRoot;
import org.springframework.security.messaging.access.intercept.ChannelSecurityInterceptor;
import org.springframework.security.messaging.access.intercept.MessageSecurityMetadataSource;
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
import org.springframework.web.socket.server.HandshakeFailureException;
import org.springframework.web.socket.server.HandshakeHandler;
import org.springframework.web.socket.server.support.HttpSessionHandshakeInterceptor;
import org.springframework.web.socket.sockjs.transport.handler.SockJsWebSocketHandler;
import org.springframework.web.socket.sockjs.transport.session.WebSocketServerSockJsSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

public class AbstractSecurityWebSocketMessageBrokerConfigurerTests {

	AnnotationConfigWebApplicationContext context;

	TestingAuthenticationToken messageUser;

	CsrfToken token;

	String sessionAttr;

	@Before
	public void setup() {
		this.token = new DefaultCsrfToken("header", "param", "token");
		this.sessionAttr = "sessionAttr";
		this.messageUser = new TestingAuthenticationToken("user", "pass", "ROLE_USER");
	}

	@After
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void simpleRegistryMappings() {
		loadConfig(SockJsSecurityConfig.class);

		clientInboundChannel().send(message("/permitAll"));

		try {
			clientInboundChannel().send(message("/denyAll"));
			fail("Expected Exception");
		}
		catch (MessageDeliveryException expected) {
			assertThat(expected.getCause()).isInstanceOf(AccessDeniedException.class);
		}
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

		try {
			messageChannel.send(message);
			fail("Expected Exception");
		}
		catch (MessageDeliveryException success) {
			assertThat(success.getCause()).isInstanceOf(MissingCsrfTokenException.class);
		}
	}

	@Test
	public void csrfProtectionForConnect() {
		loadConfig(SockJsSecurityConfig.class);

		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		Message<?> message = message(headers, "/authentication");
		MessageChannel messageChannel = clientInboundChannel();

		try {
			messageChannel.send(message);
			fail("Expected Exception");
		}
		catch (MessageDeliveryException success) {
			assertThat(success.getCause()).isInstanceOf(MissingCsrfTokenException.class);
		}
	}

	@Test
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
		CsrfChannelInterceptor csrfChannelInterceptor = this.context.getBean(CsrfChannelInterceptor.class);

		assertThat(((AbstractMessageChannel) messageChannel).getInterceptors()).contains(csrfChannelInterceptor);
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
	public void msmsRegistryCustomPatternMatcher() {
		loadConfig(MsmsRegistryCustomPatternMatcherConfig.class);

		clientInboundChannel().send(message("/app/a.b"));

		try {
			clientInboundChannel().send(message("/app/a.b.c"));
			fail("Expected Exception");
		}
		catch (MessageDeliveryException expected) {
			assertThat(expected.getCause()).isInstanceOf(AccessDeniedException.class);
		}
	}

	@Test
	public void overrideMsmsRegistryCustomPatternMatcher() {
		loadConfig(OverrideMsmsRegistryCustomPatternMatcherConfig.class);

		clientInboundChannel().send(message("/app/a/b"));

		try {
			clientInboundChannel().send(message("/app/a/b/c"));
			fail("Expected Exception");
		}
		catch (MessageDeliveryException expected) {
			assertThat(expected.getCause()).isInstanceOf(AccessDeniedException.class);
		}
	}

	@Test
	public void defaultPatternMatcher() {
		loadConfig(DefaultPatternMatcherConfig.class);

		clientInboundChannel().send(message("/app/a/b"));

		try {
			clientInboundChannel().send(message("/app/a/b/c"));
			fail("Expected Exception");
		}
		catch (MessageDeliveryException expected) {
			assertThat(expected.getCause()).isInstanceOf(AccessDeniedException.class);
		}
	}

	@Test
	public void customExpression() {
		loadConfig(CustomExpressionConfig.class);

		clientInboundChannel().send(message("/denyRob"));

		this.messageUser = new TestingAuthenticationToken("rob", "password", "ROLE_USER");
		try {
			clientInboundChannel().send(message("/denyRob"));
			fail("Expected Exception");
		}
		catch (MessageDeliveryException expected) {
			assertThat(expected.getCause()).isInstanceOf(AccessDeniedException.class);
		}
	}

	@Test
	public void channelSecurityInterceptorUsesMetadataSourceBeanWhenProxyingDisabled() {

		loadConfig(SockJsProxylessSecurityConfig.class);

		ChannelSecurityInterceptor channelSecurityInterceptor = this.context.getBean(ChannelSecurityInterceptor.class);
		MessageSecurityMetadataSource messageSecurityMetadataSource = this.context
				.getBean(MessageSecurityMetadataSource.class);

		assertThat(channelSecurityInterceptor.obtainSecurityMetadataSource()).isSameAs(messageSecurityMetadataSource);
	}

	@Test
	public void securityContextChannelInterceptorDefinedByBean() {
		loadConfig(SockJsProxylessSecurityConfig.class);

		MessageChannel messageChannel = clientInboundChannel();
		SecurityContextChannelInterceptor securityContextChannelInterceptor = this.context
				.getBean(SecurityContextChannelInterceptor.class);

		assertThat(((AbstractMessageChannel) messageChannel).getInterceptors())
				.contains(securityContextChannelInterceptor);
	}

	@Test
	public void inboundChannelSecurityDefinedByBean() {
		loadConfig(SockJsProxylessSecurityConfig.class);

		MessageChannel messageChannel = clientInboundChannel();
		ChannelSecurityInterceptor inboundChannelSecurity = this.context.getBean(ChannelSecurityInterceptor.class);

		assertThat(((AbstractMessageChannel) messageChannel).getInterceptors()).contains(inboundChannelSecurity);
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

	private MessageChannel clientInboundChannel() {
		return this.context.getBean("clientInboundChannel", MessageChannel.class);
	}

	private void loadConfig(Class<?>... configs) {
		this.context = new AnnotationConfigWebApplicationContext();
		this.context.register(configs);
		this.context.setServletConfig(new MockServletConfig());
		this.context.refresh();
	}

	@Configuration
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class MsmsRegistryCustomPatternMatcherConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

		// @formatter:off
		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry
				.addEndpoint("/other")
				.setHandshakeHandler(testHandshakeHandler());
		}
		// @formatter:on

		// @formatter:off
		@Override
		protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
			messages
				.simpDestMatchers("/app/a.*").permitAll()
				.anyMessage().denyAll();
		}
		// @formatter:on

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.setPathMatcher(new AntPathMatcher("."));
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/app");
		}

		@Bean
		public TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Configuration
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class OverrideMsmsRegistryCustomPatternMatcherConfig
			extends AbstractSecurityWebSocketMessageBrokerConfigurer {

		// @formatter:off
		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry
				.addEndpoint("/other")
				.setHandshakeHandler(testHandshakeHandler());
		}
		// @formatter:on

		// @formatter:off
		@Override
		protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
			messages
				.simpDestPathMatcher(new AntPathMatcher())
				.simpDestMatchers("/app/a/*").permitAll()
				.anyMessage().denyAll();
		}
		// @formatter:on

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.setPathMatcher(new AntPathMatcher("."));
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/app");
		}

		@Bean
		public TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Configuration
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class DefaultPatternMatcherConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

		// @formatter:off
		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry
				.addEndpoint("/other")
				.setHandshakeHandler(testHandshakeHandler());
		}
		// @formatter:on

		// @formatter:off
		@Override
		protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
			messages
				.simpDestMatchers("/app/a/*").permitAll()
				.anyMessage().denyAll();
		}
		// @formatter:on

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/app");
		}

		@Bean
		public TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Configuration
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class CustomExpressionConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

		// @formatter:off
		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry
				.addEndpoint("/other")
				.setHandshakeHandler(testHandshakeHandler());
		}
		// @formatter:on

		// @formatter:off
		@Override
		protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
			messages
				.anyMessage().access("denyRob()");
		}
		// @formatter:on

		@Bean
		public static SecurityExpressionHandler<Message<Object>> messageSecurityExpressionHandler() {
			return new DefaultMessageSecurityExpressionHandler<Object>() {
				@Override
				protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
						Message<Object> invocation) {
					return new MessageSecurityExpressionRoot(authentication, invocation) {
						public boolean denyRob() {
							Authentication auth = getAuthentication();
							return auth != null && !"rob".equals(auth.getName());
						}
					};
				}
			};
		}

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/app");
		}

		@Bean
		public TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Controller
	static class MyController {

		String authenticationPrincipal;

		MyCustomArgument myCustomArgument;

		@MessageMapping("/authentication")
		public void authentication(@AuthenticationPrincipal String un) {
			this.authenticationPrincipal = un;
		}

		@MessageMapping("/myCustom")
		public void myCustom(MyCustomArgument myCustomArgument) {
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
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class SockJsSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry.addEndpoint("/other").setHandshakeHandler(testHandshakeHandler()).withSockJS()
					.setInterceptors(new HttpSessionHandshakeInterceptor());

			registry.addEndpoint("/chat").setHandshakeHandler(testHandshakeHandler()).withSockJS()
					.setInterceptors(new HttpSessionHandshakeInterceptor());
		}

		// @formatter:off
		@Override
		protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
			messages
				.simpDestMatchers("/permitAll/**").permitAll()
				.simpDestMatchers("/beanResolver/**").access("@security.check()")
				.anyMessage().denyAll();
		}
		// @formatter:on

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/permitAll", "/denyAll");
		}

		@Bean
		public MyController myController() {
			return new MyController();
		}

		@Bean
		public TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

		@Bean
		public SecurityCheck security() {
			return new SecurityCheck();
		}

		static class SecurityCheck {

			private boolean check;

			public boolean check() {
				this.check = !this.check;
				return this.check;
			}

		}

	}

	@Configuration
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class NoInboundSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry.addEndpoint("/other").withSockJS().setInterceptors(new HttpSessionHandshakeInterceptor());

			registry.addEndpoint("/chat").withSockJS().setInterceptors(new HttpSessionHandshakeInterceptor());
		}

		@Override
		protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
		}

		@Override
		public void configureMessageBroker(MessageBrokerRegistry registry) {
			registry.enableSimpleBroker("/queue/", "/topic/");
			registry.setApplicationDestinationPrefixes("/permitAll", "/denyAll");
		}

		@Bean
		public MyController myController() {
			return new MyController();
		}

	}

	@Configuration
	static class CsrfDisabledSockJsSecurityConfig extends SockJsSecurityConfig {

		@Override
		protected boolean sameOriginDisabled() {
			return true;
		}

	}

	@Configuration
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class WebSocketSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry.addEndpoint("/websocket").setHandshakeHandler(testHandshakeHandler())
					.addInterceptors(new HttpSessionHandshakeInterceptor());
		}

		// @formatter:off
		@Override
		protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
			messages
				.simpDestMatchers("/permitAll/**").permitAll()
				.simpDestMatchers("/customExpression/**").access("denyRob")
				.anyMessage().denyAll();
		}
		// @formatter:on

		@Bean
		public TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSocketMessageBroker
	@Import(SyncExecutorConfig.class)
	static class SockJsProxylessSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

		private ApplicationContext context;

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry.addEndpoint("/chat").setHandshakeHandler(this.context.getBean(TestHandshakeHandler.class))
					.withSockJS().setInterceptors(new HttpSessionHandshakeInterceptor());
		}

		@Autowired
		public void setContext(ApplicationContext context) {
			this.context = context;
		}

		// @formatter:off
		@Override
		protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
			messages
					.anyMessage().denyAll();
		}
		// @formatter:on

		@Bean
		public TestHandshakeHandler testHandshakeHandler() {
			return new TestHandshakeHandler();
		}

	}

	@Configuration
	static class SyncExecutorConfig {

		@Bean
		public static SyncExecutorSubscribableChannelPostProcessor postProcessor() {
			return new SyncExecutorSubscribableChannelPostProcessor();
		}

	}

}
