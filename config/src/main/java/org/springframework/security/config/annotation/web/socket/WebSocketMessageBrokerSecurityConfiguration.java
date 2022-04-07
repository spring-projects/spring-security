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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

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
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.messaging.context.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
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

/**
 * Allows configuring WebSocket Authorization.
 *
 * <p>
 * For example:
 * </p>
 *
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class WebSocketSecurityConfig {
 *
 * 	&#064;Bean
 * 	AuthorizationManager&lt;Message&lt;?&gt;&gt; (AuthorizationManagerMessageMatcherRegistry messages) {
 * 		messages.simpDestMatchers(&quot;/user/queue/errors&quot;).permitAll()
 * 				.simpDestMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;).anyMessage()
 * 				.authenticated();
 *
 *		return messages.build();
 * 	}
 * }
 * </pre>
 *
 * @author Josh Cummings
 * @since 5.7
 */
@Order(Ordered.HIGHEST_PRECEDENCE + 100)
@Import(MessageMatcherAuthorizationManagerConfiguration.class)
final class WebSocketMessageBrokerSecurityConfiguration
		implements WebSocketMessageBrokerConfigurer, SmartInitializingSingleton {

	private static final String SIMPLE_URL_HANDLER_MAPPING_BEAN_NAME = "stompWebSocketHandlerMapping";

	private static final AuthorizationManager<Message<?>> ANY_MESSAGE_AUTHENTICATED = MessageMatcherDelegatingAuthorizationManager
			.builder().add(MessageMatcher.ANY_MESSAGE, AuthenticatedAuthorizationManager.authenticated()).build();

	private ChannelInterceptor securityContextChannelInterceptor = new SecurityContextChannelInterceptor();

	private ChannelInterceptor csrfChannelInterceptor = new CsrfChannelInterceptor();

	private AuthorizationChannelInterceptor authorizationChannelInterceptor = new AuthorizationChannelInterceptor(
			ANY_MESSAGE_AUTHENTICATED);

	private Consumer<List<ChannelInterceptor>> interceptorsCustomizer = (interceptors) -> {
	};

	private ApplicationContext context;

	private AbstractSecurityWebSocketMessageBrokerConfigurer configurer;

	WebSocketMessageBrokerSecurityConfiguration(ApplicationContext context) {
		this.context = context;
	}

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
		if (this.configurer != null) {
			return;
		}
		argumentResolvers.add(new AuthenticationPrincipalArgumentResolver());
	}

	@Override
	public void configureClientInboundChannel(ChannelRegistration registration) {
		if (this.configurer != null) {
			return;
		}
		this.authorizationChannelInterceptor
				.setAuthorizationEventPublisher(new SpringAuthorizationEventPublisher(this.context));
		List<ChannelInterceptor> interceptors = new ArrayList<>(Arrays.asList(this.securityContextChannelInterceptor,
				this.csrfChannelInterceptor, this.authorizationChannelInterceptor));
		this.interceptorsCustomizer.accept(interceptors);
		registration.interceptors(interceptors.toArray(new ChannelInterceptor[0]));
	}

	@Autowired(required = false)
	void setSecurityContextChannelInterceptor(SecurityContextChannelInterceptor interceptor) {
		this.securityContextChannelInterceptor = interceptor;
	}

	@Autowired(required = false)
	void setCsrfChannelInterceptor(CsrfChannelInterceptor csrfChannelInterceptor) {
		this.csrfChannelInterceptor = csrfChannelInterceptor;
	}

	@Autowired(required = false)
	void setAuthorizationManager(AuthorizationManager<Message<?>> authorizationManager) {
		this.authorizationChannelInterceptor = new AuthorizationChannelInterceptor(authorizationManager);
	}

	@Autowired(required = false)
	void setInterceptorsCustomizer(Consumer<List<ChannelInterceptor>> interceptorsCustomizer) {
		this.interceptorsCustomizer = interceptorsCustomizer;
	}

	@Autowired(required = false)
	@Deprecated
	void setAbstractSecurityWebSocketMessageBrokerConfigurer(
			AbstractSecurityWebSocketMessageBrokerConfigurer configurer) {
		this.configurer = configurer;
	}

	@Override
	public void afterSingletonsInstantiated() {
		if (this.configurer != null) {
			return;
		}
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
