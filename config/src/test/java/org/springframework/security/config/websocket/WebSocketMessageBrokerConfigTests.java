/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.websocket;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import org.assertj.core.api.ThrowableAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.core.MethodParameter;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.GenericMessage;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.messaging.access.expression.DefaultMessageSecurityExpressionHandler;
import org.springframework.security.messaging.access.expression.MessageSecurityExpressionRoot;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.DeferredCsrfToken;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeFailureException;
import org.springframework.web.socket.server.HandshakeHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.springframework.security.web.csrf.CsrfTokenAssert.assertThatCsrfToken;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class WebSocketMessageBrokerConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/websocket/WebSocketMessageBrokerConfigTests";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	private MessageChannel clientInboundChannel;

	@Autowired(required = false)
	private MessageController messageController;

	@Autowired(required = false)
	private MessageWithArgumentController messageWithArgumentController;

	@Autowired(required = false)
	private TestHandshakeHandler testHandshakeHandler;

	private CsrfToken token = new DefaultCsrfToken("header", "param", "token");

	@Test
	public void sendWhenNoIdSpecifiedThenIntegratesWithClientInboundChannel() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();
		this.clientInboundChannel.send(message("/permitAll"));
		assertThatExceptionOfType(Exception.class).isThrownBy(() -> this.clientInboundChannel.send(message("/denyAll")))
			.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendWhenAnonymousMessageWithConnectMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		headers.setNativeHeader(this.token.getHeaderName(), this.token.getToken());
		this.clientInboundChannel.send(message("/permitAll", headers));
	}

	@Test
	public void sendWhenAnonymousMessageWithConnectAckMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.CONNECT_ACK);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithDisconnectMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.DISCONNECT);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithDisconnectAckMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.DISCONNECT_ACK);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithHeartbeatMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.HEARTBEAT);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithMessageMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.MESSAGE);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithOtherMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.OTHER);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithSubscribeMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.SUBSCRIBE);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithUnsubscribeMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.UNSUBSCRIBE);
		send(message);
	}

	@Test
	public void sendWhenNoIdSpecifiedThenIntegratesWithAuthorizationManager() {
		this.spring.configLocations(xml("NoIdAuthorizationManager")).autowire();
		this.clientInboundChannel.send(message("/permitAll"));
		assertThatExceptionOfType(Exception.class).isThrownBy(() -> this.clientInboundChannel.send(message("/denyAll")))
			.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendWhenAnonymousMessageWithConnectMessageTypeThenAuthorizationManagerPermits() {
		this.spring.configLocations(xml("NoIdAuthorizationManager")).autowire();
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		headers.setNativeHeader(this.token.getHeaderName(), this.token.getToken());
		this.clientInboundChannel.send(message("/permitAll", headers));
	}

	@Test
	public void sendWhenAnonymousMessageWithConnectAckMessageTypeThenAuthorizationManagerPermits() {
		this.spring.configLocations(xml("NoIdAuthorizationManager")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.CONNECT_ACK);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithDisconnectMessageTypeThenAuthorizationManagerPermits() {
		this.spring.configLocations(xml("NoIdAuthorizationManager")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.DISCONNECT);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithDisconnectAckMessageTypeThenAuthorizationManagerPermits() {
		this.spring.configLocations(xml("NoIdAuthorizationManager")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.DISCONNECT_ACK);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithHeartbeatMessageTypeThenAuthorizationManagerPermits() {
		this.spring.configLocations(xml("NoIdAuthorizationManager")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.HEARTBEAT);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithMessageMessageTypeThenAuthorizationManagerPermits() {
		this.spring.configLocations(xml("NoIdAuthorizationManager")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.MESSAGE);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithOtherMessageTypeThenAuthorizationManagerPermits() {
		this.spring.configLocations(xml("NoIdAuthorizationManager")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.OTHER);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithSubscribeMessageTypeThenAuthorizationManagerPermits() {
		this.spring.configLocations(xml("NoIdAuthorizationManager")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.SUBSCRIBE);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithUnsubscribeMessageTypeThenAuthorizationManagerPermits() {
		this.spring.configLocations(xml("NoIdAuthorizationManager")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.UNSUBSCRIBE);
		send(message);
	}

	@Test
	public void sendWhenAnonymousMessageWithCustomSecurityContextHolderStrategyAndAuthorizationManagerThenUses() {
		this.spring.configLocations(xml("WithSecurityContextHolderStrategy")).autowire();
		SecurityContextHolderStrategy strategy = this.spring.getContext().getBean(SecurityContextHolderStrategy.class);
		Message<?> message = message("/authenticated", SimpMessageType.CONNECT);
		send(message);
		verify(strategy).getContext();
	}

	@Test
	public void sendWhenConnectWithoutCsrfTokenThenDenied() {
		this.spring.configLocations(xml("SyncConfig")).autowire();
		Message<?> message = message("/message", SimpMessageType.CONNECT);
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(InvalidCsrfTokenException.class);
	}

	@Test
	public void sendWhenConnectWithSameOriginDisabledThenCsrfTokenNotRequired() {
		this.spring.configLocations(xml("SyncSameOriginDisabledConfig")).autowire();
		Message<?> message = message("/message", SimpMessageType.CONNECT);
		send(message);
	}

	@Test
	public void sendWhenInterceptWiredForMessageTypeThenDeniesOnTypeMismatch() {
		this.spring.configLocations(xml("MessageInterceptTypeConfig")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.MESSAGE);
		send(message);
		message = message("/permitAll", SimpMessageType.UNSUBSCRIBE);
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
		message = message("/anyOther", SimpMessageType.MESSAGE);
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendWhenInterceptWiredForMessageTypeThenAuthorizationManagerDeniesOnTypeMismatch() {
		this.spring.configLocations(xml("MessageInterceptTypeAuthorizationManager")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.MESSAGE);
		send(message);
		message = message("/permitAll", SimpMessageType.UNSUBSCRIBE);
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
		message = message("/anyOther", SimpMessageType.MESSAGE);
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendWhenInterceptWiredForSubscribeTypeThenDeniesOnTypeMismatch() {
		this.spring.configLocations(xml("SubscribeInterceptTypeConfig")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.SUBSCRIBE);
		send(message);
		message = message("/permitAll", SimpMessageType.UNSUBSCRIBE);
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
		message = message("/anyOther", SimpMessageType.SUBSCRIBE);
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendWhenInterceptWiredForSubscribeTypeThenAuthorizationManagerDeniesOnTypeMismatch() {
		this.spring.configLocations(xml("SubscribeInterceptTypeAuthorizationManager")).autowire();
		Message<?> message = message("/permitAll", SimpMessageType.SUBSCRIBE);
		send(message);
		message = message("/permitAll", SimpMessageType.UNSUBSCRIBE);
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
		message = message("/anyOther", SimpMessageType.SUBSCRIBE);
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void configureWhenUsingConnectMessageTypeThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
			.isThrownBy(() -> this.spring.configLocations(xml("ConnectInterceptTypeConfig")).autowire());
	}

	@Test
	public void configureWhenUsingConnectAckMessageTypeThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
			.isThrownBy(() -> this.spring.configLocations(xml("ConnectAckInterceptTypeConfig")).autowire());
	}

	@Test
	public void configureWhenUsingDisconnectMessageTypeThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
			.isThrownBy(() -> this.spring.configLocations(xml("DisconnectInterceptTypeConfig")).autowire());
	}

	@Test
	public void configureWhenUsingDisconnectAckMessageTypeThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
			.isThrownBy(() -> this.spring.configLocations(xml("DisconnectAckInterceptTypeConfig")).autowire());
	}

	@Test
	public void configureWhenUsingHeartbeatMessageTypeThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
			.isThrownBy(() -> this.spring.configLocations(xml("HeartbeatInterceptTypeConfig")).autowire());
	}

	@Test
	public void configureWhenUsingOtherMessageTypeThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
			.isThrownBy(() -> this.spring.configLocations(xml("OtherInterceptTypeConfig")).autowire());
	}

	@Test
	public void configureWhenUsingUnsubscribeMessageTypeThenAutowireFails() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
			.isThrownBy(() -> this.spring.configLocations(xml("UnsubscribeInterceptTypeConfig")).autowire());
	}

	@Test
	public void sendWhenNoIdMessageThenAuthenticationPrincipalResolved() {
		this.spring.configLocations(xml("SyncConfig")).autowire();
		this.clientInboundChannel.send(message("/message"));
		assertThat(this.messageController.username).isEqualTo("anonymous");
	}

	@Test
	public void sendMessageWhenMetaAnnotationThenAuthenticationPrincipalResolved() {
		this.spring.configLocations(xml("SyncConfig")).autowire();
		Authentication harold = new TestingAuthenticationToken("harold", "password", "ROLE_USER");
		try {
			getSecurityContextHolderStrategy().setContext(new SecurityContextImpl(harold));
			this.clientInboundChannel.send(message("/hi"));
			assertThat(this.spring.getContext().getBean(MessageController.class).message).isEqualTo("Hi, Harold!");
			Authentication user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
			getSecurityContextHolderStrategy().setContext(new SecurityContextImpl(user));
			this.clientInboundChannel.send(message("/hi"));
			assertThat(this.spring.getContext().getBean(MessageController.class).message).isEqualTo("Hi, Stranger!");
		}
		finally {
			getSecurityContextHolderStrategy().clearContext();
		}
	}

	@Test
	public void requestWhenConnectMessageThenUsesCsrfTokenHandshakeInterceptor() throws Exception {
		this.spring.configLocations(xml("SyncConfig")).autowire();
		WebApplicationContext context = this.spring.getContext();
		MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).build();
		String csrfAttributeName = CsrfToken.class.getName();
		String customAttributeName = this.getClass().getName();
		MvcResult result = mvc
			.perform(get("/app").requestAttr(DeferredCsrfToken.class.getName(), new TestDeferredCsrfToken(this.token))
				.sessionAttr(customAttributeName, "attributeValue"))
			.andReturn();
		CsrfToken handshakeToken = (CsrfToken) this.testHandshakeHandler.attributes.get(csrfAttributeName);
		String handshakeValue = (String) this.testHandshakeHandler.attributes.get(customAttributeName);
		String sessionValue = (String) result.getRequest().getSession().getAttribute(customAttributeName);
		assertThatCsrfToken(handshakeToken).isEqualTo(this.token).withFailMessage("CsrfToken is populated");
		assertThat(handshakeValue).isEqualTo(sessionValue)
			.withFailMessage("Explicitly listed session variables are not overridden");
	}

	@Test
	public void requestWhenConnectMessageAndUsingSockJsThenUsesCsrfTokenHandshakeInterceptor() throws Exception {
		this.spring.configLocations(xml("SyncSockJsConfig")).autowire();
		WebApplicationContext context = this.spring.getContext();
		MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).build();
		String csrfAttributeName = CsrfToken.class.getName();
		String customAttributeName = this.getClass().getName();
		MvcResult result = mvc
			.perform(get("/app/289/tpyx6mde/websocket")
				.requestAttr(DeferredCsrfToken.class.getName(), new TestDeferredCsrfToken(this.token))
				.sessionAttr(customAttributeName, "attributeValue"))
			.andReturn();
		CsrfToken handshakeToken = (CsrfToken) this.testHandshakeHandler.attributes.get(csrfAttributeName);
		String handshakeValue = (String) this.testHandshakeHandler.attributes.get(customAttributeName);
		String sessionValue = (String) result.getRequest().getSession().getAttribute(customAttributeName);
		assertThatCsrfToken(handshakeToken).isEqualTo(this.token).withFailMessage("CsrfToken is populated");
		assertThat(handshakeValue).isEqualTo(sessionValue)
			.withFailMessage("Explicitly listed session variables are not overridden");
	}

	@Test
	public void sendWhenNoIdSpecifiedThenCustomArgumentResolversAreNotOverridden() {
		this.spring.configLocations(xml("SyncCustomArgumentResolverConfig")).autowire();
		this.clientInboundChannel.send(message("/message-with-argument"));
		assertThat(this.messageWithArgumentController.messageArgument).isNotNull();
	}

	@Test
	public void sendWhenUsingCustomPathMatcherThenSecurityAppliesIt() {
		this.spring.configLocations(xml("CustomPathMatcherConfig")).autowire();
		Message<?> message = message("/denyAll.a");
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
		message = message("/denyAll.a.b");
		send(message);
	}

	@Test
	public void sendWhenUsingCustomPathMatcherThenAuthorizationManagerAppliesIt() {
		this.spring.configLocations(xml("CustomPathMatcherAuthorizationManager")).autowire();
		Message<?> message = message("/denyAll.a");
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
		message = message("/denyAll.a.b");
		send(message);
	}

	@Test
	public void sendWhenIdSpecifiedThenSecurityDoesNotIntegrateWithClientInboundChannel() {
		this.spring.configLocations(xml("IdConfig")).autowire();
		Message<?> message = message("/denyAll");
		send(message);
	}

	@Test
	@WithMockUser
	public void sendWhenIdSpecifiedAndExplicitlyIntegratedWhenBrokerUsesClientInboundChannel() {
		this.spring.configLocations(xml("IdIntegratedConfig")).autowire();
		Message<?> message = message("/denyAll");
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendWhenNoIdSpecifiedThenSecurityDoesntOverrideCustomInterceptors() {
		this.spring.configLocations(xml("CustomInterceptorConfig")).autowire();
		Message<?> message = message("/throwAll");
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	@WithMockUser(username = "nile")
	public void sendWhenCustomExpressionHandlerThenAuthorizesAccordingly() {
		this.spring.configLocations(xml("CustomExpressionHandlerConfig")).autowire();
		Message<?> message = message("/denyNile");
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	@WithMockUser(username = "nile")
	public void sendWhenCustomExpressionHandlerThenAuthorizationManagerAuthorizesAccordingly() {
		this.spring.configLocations(xml("CustomExpressionHandlerAuthorizationManager")).autowire();
		Message<?> message = message("/denyNile");
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendWhenCustomAuthorizationManagerThenAuthorizesAccordingly() {
		this.spring.configLocations(xml("CustomAuthorizationManagerConfig")).autowire();
		AuthorizationManager<Message<?>> authorizationManager = this.spring.getContext()
			.getBean(AuthorizationManager.class);
		given(authorizationManager.check(any(), any())).willReturn(new AuthorizationDecision(false));
		given(authorizationManager.authorize(any(), any())).willCallRealMethod();
		Message<?> message = message("/any");
		assertThatExceptionOfType(Exception.class).isThrownBy(send(message))
			.withCauseInstanceOf(AccessDeniedException.class);
		verify(authorizationManager).check(any(), any());
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	private ThrowableAssert.ThrowingCallable send(Message<?> message) {
		return () -> this.clientInboundChannel.send(message);
	}

	private Message<?> message(String destination) {
		return message(destination, SimpMessageType.MESSAGE);
	}

	private Message<?> message(String destination, SimpMessageType type) {
		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(type);
		return message(destination, headers);
	}

	private Message<?> message(String destination, SimpMessageHeaderAccessor headers) {
		headers.setSessionId("123");
		headers.setSessionAttributes(new HashMap<>());
		headers.setDestination(destination);
		SecurityContextHolderStrategy strategy = getSecurityContextHolderStrategy();
		if (strategy.getContext().getAuthentication() != null) {
			headers.setUser(strategy.getContext().getAuthentication());
		}
		headers.getSessionAttributes().put(CsrfToken.class.getName(), this.token);
		return new GenericMessage<>("hi", headers.getMessageHeaders());
	}

	private SecurityContextHolderStrategy getSecurityContextHolderStrategy() {
		String[] names = this.spring.getContext().getBeanNamesForType(SecurityContextHolderStrategy.class);
		if (names.length == 1) {
			return this.spring.getContext().getBean(names[0], SecurityContextHolderStrategy.class);
		}
		return SecurityContextHolder.getContextHolderStrategy();
	}

	private static final class TestDeferredCsrfToken implements DeferredCsrfToken {

		private final CsrfToken csrfToken;

		TestDeferredCsrfToken(CsrfToken csrfToken) {
			this.csrfToken = csrfToken;
		}

		@Override
		public CsrfToken get() {
			return this.csrfToken;
		}

		@Override
		public boolean isGenerated() {
			return false;
		}

	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	@AuthenticationPrincipal(expression = "#this.equals('{value}')")
	@interface IsUser {

		String value() default "user";

	}

	@Controller
	static class MessageController {

		String username;

		String message;

		@MessageMapping("/message")
		void authentication(@AuthenticationPrincipal String username) {
			this.username = username;
		}

		@MessageMapping("/hi")
		void sayHello(@IsUser("harold") boolean isHarold) {
			this.message = isHarold ? "Hi, Harold!" : "Hi, Stranger!";
		}

	}

	@Controller
	static class MessageWithArgumentController {

		MessageArgument messageArgument;

		@MessageMapping("/message-with-argument")
		void myCustom(MessageArgument messageArgument) {
			this.messageArgument = messageArgument;
		}

	}

	static class MessageArgument {

		MessageArgument(String notDefaultConstructor) {
		}

	}

	static class MessageArgumentResolver implements HandlerMethodArgumentResolver {

		@Override
		public boolean supportsParameter(MethodParameter parameter) {
			return parameter.getParameterType().isAssignableFrom(MessageArgument.class);
		}

		@Override
		public Object resolveArgument(MethodParameter parameter, Message<?> message) {
			return new MessageArgument("");
		}

	}

	static class TestHandshakeHandler implements HandshakeHandler {

		Map<String, Object> attributes;

		@Override
		public boolean doHandshake(ServerHttpRequest request,
				org.springframework.http.server.ServerHttpResponse response, WebSocketHandler wsHandler,
				Map<String, Object> attributes) throws HandshakeFailureException {
			this.attributes = attributes;
			return true;
		}

	}

	static class InboundExecutorPostProcessor implements BeanDefinitionRegistryPostProcessor {

		@Override
		public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
			BeanDefinition inbound = registry.getBeanDefinition("clientInboundChannel");
			inbound.getConstructorArgumentValues()
				.addIndexedArgumentValue(0, new RootBeanDefinition(SyncTaskExecutor.class));
		}

		@Override
		public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
		}

	}

	static class ExceptingInterceptor implements ChannelInterceptor {

		@Override
		public Message<?> preSend(Message<?> message, MessageChannel channel) {
			throw new UnsupportedOperationException("no");
		}

	}

	static class DenyNileMessageSecurityExpressionHandler extends DefaultMessageSecurityExpressionHandler<Object> {

		@Override
		protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
				Message<Object> invocation) {
			return new MessageSecurityExpressionRoot(authentication, invocation) {
				public boolean denyNile() {
					Authentication auth = getAuthentication();
					return auth != null && !"nile".equals(auth.getName());
				}
			};
		}

		@Override
		public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication,
				Message<Object> message) {
			return new StandardEvaluationContext(new MessageSecurityExpressionRoot(authentication, message) {
				public boolean denyNile() {
					Authentication auth = getAuthentication();
					return auth != null && !"nile".equals(auth.getName());
				}
			});
		}

	}

}
