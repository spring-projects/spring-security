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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.micrometer.observation.ObservationRegistry;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.messaging.context.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.security.messaging.web.csrf.CsrfChannelInterceptor;
import org.springframework.security.messaging.web.socket.server.CsrfTokenHandshakeInterceptor;
import org.springframework.util.Assert;
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.server.HandshakeInterceptor;
import org.springframework.web.socket.server.support.WebSocketHttpRequestHandler;
import org.springframework.web.socket.sockjs.SockJsService;
import org.springframework.web.socket.sockjs.support.SockJsHttpRequestHandler;
import org.springframework.web.socket.sockjs.transport.TransportHandlingSockJsService;

@Order(Ordered.HIGHEST_PRECEDENCE + 100)
@Import(MessageMatcherAuthorizationManagerConfiguration.class)
final class WebSocketMessageBrokerSecurityConfiguration
		implements WebSocketMessageBrokerConfigurer, SmartInitializingSingleton {

	private static final String SIMPLE_URL_HANDLER_MAPPING_BEAN_NAME = "stompWebSocketHandlerMapping";

	private MessageMatcherDelegatingAuthorizationManager b;

	private static final AuthorizationManager<Message<?>> ANY_MESSAGE_AUTHENTICATED = MessageMatcherDelegatingAuthorizationManager
			.builder().anyMessage().authenticated().build();

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private final SecurityContextChannelInterceptor securityContextChannelInterceptor = new SecurityContextChannelInterceptor();

	private final ChannelInterceptor csrfChannelInterceptor = new CsrfChannelInterceptor();

	private AuthorizationManager<Message<?>> authorizationManager = ANY_MESSAGE_AUTHENTICATED;

	private ObservationRegistry observationRegistry = ObservationRegistry.NOOP;

	private ApplicationContext context;

	WebSocketMessageBrokerSecurityConfiguration(ApplicationContext context) {
		this.context = context;
	}

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
		AuthenticationPrincipalArgumentResolver resolver = new AuthenticationPrincipalArgumentResolver();
		resolver.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		argumentResolvers.add(resolver);
	}

	@Override
	public void configureClientInboundChannel(ChannelRegistration registration) {
		AuthorizationManager<Message<?>> manager = this.authorizationManager;
		if (!this.observationRegistry.isNoop()) {
			manager = new ObservationAuthorizationManager<>(this.observationRegistry, manager);
		}
		AuthorizationChannelInterceptor interceptor = new AuthorizationChannelInterceptor(manager);
		interceptor.setAuthorizationEventPublisher(new SpringAuthorizationEventPublisher(this.context));
		interceptor.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		this.securityContextChannelInterceptor.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		registration.interceptors(this.securityContextChannelInterceptor, this.csrfChannelInterceptor, interceptor);
	}

	@Autowired(required = false)
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	@Autowired(required = false)
	void setAuthorizationManager(AuthorizationManager<Message<?>> authorizationManager) {
		this.authorizationManager = authorizationManager;
	}

	@Autowired(required = false)
	void setObservationRegistry(ObservationRegistry observationRegistry) {
		this.observationRegistry = observationRegistry;
	}

	@Override
	public void afterSingletonsInstantiated() {
		SimpleUrlHandlerMapping mapping = getBeanOrNull(SIMPLE_URL_HANDLER_MAPPING_BEAN_NAME,
				SimpleUrlHandlerMapping.class);
		if (mapping == null) {
			return;
		}
		configureCsrf(mapping);
	}

	private <T> T getBeanOrNull(String name, Class<T> type) {
		Map<String, T> beans = this.context.getBeansOfType(type);
		return beans.get(name);
	}

	private void configureCsrf(SimpleUrlHandlerMapping mapping) {
		Map<String, Object> mappings = mapping.getHandlerMap();
		for (Object object : mappings.values()) {
			if (object instanceof SockJsHttpRequestHandler) {
				setHandshakeInterceptors((SockJsHttpRequestHandler) object);
			}
			else if (object instanceof WebSocketHttpRequestHandler) {
				setHandshakeInterceptors((WebSocketHttpRequestHandler) object);
			}
			else {
				throw new IllegalStateException(
						"Bean " + SIMPLE_URL_HANDLER_MAPPING_BEAN_NAME + " is expected to contain mappings to either a "
								+ "SockJsHttpRequestHandler or a WebSocketHttpRequestHandler but got " + object);
			}
		}
	}

	private void setHandshakeInterceptors(SockJsHttpRequestHandler handler) {
		SockJsService sockJsService = handler.getSockJsService();
		Assert.state(sockJsService instanceof TransportHandlingSockJsService,
				() -> "sockJsService must be instance of TransportHandlingSockJsService got " + sockJsService);
		TransportHandlingSockJsService transportHandlingSockJsService = (TransportHandlingSockJsService) sockJsService;
		List<HandshakeInterceptor> handshakeInterceptors = transportHandlingSockJsService.getHandshakeInterceptors();
		List<HandshakeInterceptor> interceptorsToSet = new ArrayList<>(handshakeInterceptors.size() + 1);
		interceptorsToSet.add(new CsrfTokenHandshakeInterceptor());
		interceptorsToSet.addAll(handshakeInterceptors);
		transportHandlingSockJsService.setHandshakeInterceptors(interceptorsToSet);
	}

	private void setHandshakeInterceptors(WebSocketHttpRequestHandler handler) {
		List<HandshakeInterceptor> handshakeInterceptors = handler.getHandshakeInterceptors();
		List<HandshakeInterceptor> interceptorsToSet = new ArrayList<>(handshakeInterceptors.size() + 1);
		interceptorsToSet.add(new CsrfTokenHandshakeInterceptor());
		interceptorsToSet.addAll(handshakeInterceptors);
		handler.setHandshakeInterceptors(interceptorsToSet);
	}

}
