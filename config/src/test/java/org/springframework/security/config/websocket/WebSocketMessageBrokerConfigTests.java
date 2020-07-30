/*
 * Copyright 2002-2018 the original author or authors.
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

import java.util.HashMap;
import java.util.Map;

import org.assertj.core.api.ThrowableAssert;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

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
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.ChannelInterceptorAdapter;
import org.springframework.messaging.support.GenericMessage;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.messaging.access.expression.DefaultMessageSecurityExpressionHandler;
import org.springframework.security.messaging.access.expression.MessageSecurityExpressionRoot;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeFailureException;
import org.springframework.web.socket.server.HandshakeHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SecurityTestExecutionListeners
public class WebSocketMessageBrokerConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/websocket/WebSocketMessageBrokerConfigTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

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

		assertThatThrownBy(() -> this.clientInboundChannel.send(message("/denyAll")))
				.hasCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendWhenAnonymousMessageWithConnectMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();

		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		headers.setNativeHeader(this.token.getHeaderName(), this.token.getToken());

		assertThatCode(() -> this.clientInboundChannel.send(message("/permitAll", headers))).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenAnonymousMessageWithConnectAckMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();

		Message<?> message = message("/permitAll", SimpMessageType.CONNECT_ACK);

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenAnonymousMessageWithDisconnectMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();

		Message<?> message = message("/permitAll", SimpMessageType.DISCONNECT);

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenAnonymousMessageWithDisconnectAckMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();

		Message<?> message = message("/permitAll", SimpMessageType.DISCONNECT_ACK);

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenAnonymousMessageWithHeartbeatMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();

		Message<?> message = message("/permitAll", SimpMessageType.HEARTBEAT);

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenAnonymousMessageWithMessageMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();

		Message<?> message = message("/permitAll", SimpMessageType.MESSAGE);

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenAnonymousMessageWithOtherMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();

		Message<?> message = message("/permitAll", SimpMessageType.OTHER);

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenAnonymousMessageWithSubscribeMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();

		Message<?> message = message("/permitAll", SimpMessageType.SUBSCRIBE);

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenAnonymousMessageWithUnsubscribeMessageTypeThenPermitted() {
		this.spring.configLocations(xml("NoIdConfig")).autowire();

		Message<?> message = message("/permitAll", SimpMessageType.UNSUBSCRIBE);

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenConnectWithoutCsrfTokenThenDenied() {
		this.spring.configLocations(xml("SyncConfig")).autowire();

		Message<?> message = message("/message", SimpMessageType.CONNECT);

		assertThatThrownBy(send(message)).hasCauseInstanceOf(InvalidCsrfTokenException.class);
	}

	@Test
	public void sendWhenConnectWithSameOriginDisabledThenCsrfTokenNotRequired() {
		this.spring.configLocations(xml("SyncSameOriginDisabledConfig")).autowire();

		Message<?> message = message("/message", SimpMessageType.CONNECT);

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenInterceptWiredForMessageTypeThenDeniesOnTypeMismatch() {
		this.spring.configLocations(xml("MessageInterceptTypeConfig")).autowire();

		Message<?> message = message("/permitAll", SimpMessageType.MESSAGE);

		assertThatCode(send(message)).doesNotThrowAnyException();

		message = message("/permitAll", SimpMessageType.UNSUBSCRIBE);

		assertThatThrownBy(send(message)).hasCauseInstanceOf(AccessDeniedException.class);

		message = message("/anyOther", SimpMessageType.MESSAGE);

		assertThatThrownBy(send(message)).hasCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendWhenInterceptWiredForSubscribeTypeThenDeniesOnTypeMismatch() {
		this.spring.configLocations(xml("SubscribeInterceptTypeConfig")).autowire();

		Message<?> message = message("/permitAll", SimpMessageType.SUBSCRIBE);

		assertThatCode(send(message)).doesNotThrowAnyException();

		message = message("/permitAll", SimpMessageType.UNSUBSCRIBE);

		assertThatThrownBy(send(message)).hasCauseInstanceOf(AccessDeniedException.class);

		message = message("/anyOther", SimpMessageType.SUBSCRIBE);

		assertThatThrownBy(send(message)).hasCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void configureWhenUsingConnectMessageTypeThenAutowireFails() {
		ThrowingCallable bad = () -> this.spring.configLocations(xml("ConnectInterceptTypeConfig")).autowire();

		assertThatThrownBy(bad).isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenUsingConnectAckMessageTypeThenAutowireFails() {
		ThrowingCallable bad = () -> this.spring.configLocations(xml("ConnectAckInterceptTypeConfig")).autowire();

		assertThatThrownBy(bad).isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenUsingDisconnectMessageTypeThenAutowireFails() {
		ThrowingCallable bad = () -> this.spring.configLocations(xml("DisconnectInterceptTypeConfig")).autowire();

		assertThatThrownBy(bad).isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenUsingDisconnectAckMessageTypeThenAutowireFails() {
		ThrowingCallable bad = () -> this.spring.configLocations(xml("DisconnectAckInterceptTypeConfig")).autowire();

		assertThatThrownBy(bad).isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenUsingHeartbeatMessageTypeThenAutowireFails() {
		ThrowingCallable bad = () -> this.spring.configLocations(xml("HeartbeatInterceptTypeConfig")).autowire();

		assertThatThrownBy(bad).isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenUsingOtherMessageTypeThenAutowireFails() {
		ThrowingCallable bad = () -> this.spring.configLocations(xml("OtherInterceptTypeConfig")).autowire();

		assertThatThrownBy(bad).isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenUsingUnsubscribeMessageTypeThenAutowireFails() {
		ThrowingCallable bad = () -> this.spring.configLocations(xml("UnsubscribeInterceptTypeConfig")).autowire();

		assertThatThrownBy(bad).isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void sendWhenNoIdMessageThenAuthenticationPrincipalResolved() {
		this.spring.configLocations(xml("SyncConfig")).autowire();

		this.clientInboundChannel.send(message("/message"));

		assertThat(this.messageController.username).isEqualTo("anonymous");
	}

	@Test
	public void requestWhenConnectMessageThenUsesCsrfTokenHandshakeInterceptor() throws Exception {
		this.spring.configLocations(xml("SyncConfig")).autowire();

		WebApplicationContext context = this.spring.getContext();
		MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).build();

		String csrfAttributeName = CsrfToken.class.getName();
		String customAttributeName = this.getClass().getName();

		MvcResult result = mvc.perform(get("/app").requestAttr(csrfAttributeName, this.token)
				.sessionAttr(customAttributeName, "attributeValue")).andReturn();

		CsrfToken handshakeToken = (CsrfToken) this.testHandshakeHandler.attributes.get(csrfAttributeName);
		String handshakeValue = (String) this.testHandshakeHandler.attributes.get(customAttributeName);
		String sessionValue = (String) result.getRequest().getSession().getAttribute(customAttributeName);

		assertThat(handshakeToken).isEqualTo(this.token).withFailMessage("CsrfToken is populated");

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

		MvcResult result = mvc.perform(get("/app/289/tpyx6mde/websocket").requestAttr(csrfAttributeName, this.token)
				.sessionAttr(customAttributeName, "attributeValue")).andReturn();

		CsrfToken handshakeToken = (CsrfToken) this.testHandshakeHandler.attributes.get(csrfAttributeName);
		String handshakeValue = (String) this.testHandshakeHandler.attributes.get(customAttributeName);
		String sessionValue = (String) result.getRequest().getSession().getAttribute(customAttributeName);

		assertThat(handshakeToken).isEqualTo(this.token).withFailMessage("CsrfToken is populated");

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

		assertThatThrownBy(send(message)).hasCauseInstanceOf(AccessDeniedException.class);

		message = message("/denyAll.a.b");

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	public void sendWhenIdSpecifiedThenSecurityDoesNotIntegrateWithClientInboundChannel() {
		this.spring.configLocations(xml("IdConfig")).autowire();

		Message<?> message = message("/denyAll");

		assertThatCode(send(message)).doesNotThrowAnyException();
	}

	@Test
	@WithMockUser
	public void sendWhenIdSpecifiedAndExplicitlyIntegratedWhenBrokerUsesClientInboundChannel() {
		this.spring.configLocations(xml("IdIntegratedConfig")).autowire();

		Message<?> message = message("/denyAll");

		assertThatThrownBy(send(message)).hasCauseInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void sendWhenNoIdSpecifiedThenSecurityDoesntOverrideCustomInterceptors() {
		this.spring.configLocations(xml("CustomInterceptorConfig")).autowire();

		Message<?> message = message("/throwAll");

		assertThatThrownBy(send(message)).hasCauseInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	@WithMockUser(username = "nile")
	public void sendWhenCustomExpressionHandlerThenAuthorizesAccordingly() {
		this.spring.configLocations(xml("CustomExpressionHandlerConfig")).autowire();

		Message<?> message = message("/denyNile");

		assertThatThrownBy(send(message)).hasCauseInstanceOf(AccessDeniedException.class);
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

		if (SecurityContextHolder.getContext().getAuthentication() != null) {
			headers.setUser(SecurityContextHolder.getContext().getAuthentication());
		}

		headers.getSessionAttributes().put(CsrfToken.class.getName(), this.token);

		return new GenericMessage<>("hi", headers.getMessageHeaders());
	}

	@Controller
	static class MessageController {

		String username;

		@MessageMapping("/message")
		void authentication(@AuthenticationPrincipal String username) {
			this.username = username;
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
			inbound.getConstructorArgumentValues().addIndexedArgumentValue(0,
					new RootBeanDefinition(SyncTaskExecutor.class));
		}

		@Override
		public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

		}

	}

	static class ExceptingInterceptor extends ChannelInterceptorAdapter {

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

	}

}
