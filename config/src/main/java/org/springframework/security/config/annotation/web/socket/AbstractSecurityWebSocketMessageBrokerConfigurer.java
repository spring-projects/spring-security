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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver;
import org.springframework.messaging.simp.annotation.support.SimpAnnotationMethodMessageHandler;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.config.annotation.web.messaging.MessageSecurityMetadataSourceRegistry;
import org.springframework.security.messaging.access.expression.DefaultMessageSecurityExpressionHandler;
import org.springframework.security.messaging.access.expression.MessageExpressionVoter;
import org.springframework.security.messaging.access.intercept.ChannelSecurityInterceptor;
import org.springframework.security.messaging.access.intercept.MessageSecurityMetadataSource;
import org.springframework.security.messaging.context.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.security.messaging.web.csrf.CsrfChannelInterceptor;
import org.springframework.security.messaging.web.socket.server.CsrfTokenHandshakeInterceptor;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping;
import org.springframework.web.socket.config.annotation.AbstractWebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
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
 * public class WebSocketSecurityConfig extends
 * 		AbstractSecurityWebSocketMessageBrokerConfigurer {
 *
 * 	&#064;Override
 * 	protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
 * 		messages.simpDestMatchers(&quot;/user/queue/errors&quot;).permitAll()
 * 				.simpDestMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;).anyMessage()
 * 				.authenticated();
 * 	}
 * }
 * </pre>
 *
 * @since 4.0
 * @author Rob Winch
 */
@Order(Ordered.HIGHEST_PRECEDENCE + 100)
@Import(ObjectPostProcessorConfiguration.class)
public abstract class AbstractSecurityWebSocketMessageBrokerConfigurer extends AbstractWebSocketMessageBrokerConfigurer
		implements SmartInitializingSingleton {

	private final WebSocketMessageSecurityMetadataSourceRegistry inboundRegistry = new WebSocketMessageSecurityMetadataSourceRegistry();

	private SecurityExpressionHandler<Message<Object>> defaultExpressionHandler = new DefaultMessageSecurityExpressionHandler<>();

	private SecurityExpressionHandler<Message<Object>> expressionHandler;

	private ApplicationContext context;

	@Override
	public void registerStompEndpoints(StompEndpointRegistry registry) {
	}

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
		argumentResolvers.add(new AuthenticationPrincipalArgumentResolver());
	}

	@Override
	public final void configureClientInboundChannel(ChannelRegistration registration) {
		ChannelSecurityInterceptor inboundChannelSecurity = this.context.getBean(ChannelSecurityInterceptor.class);
		registration.setInterceptors(this.context.getBean(SecurityContextChannelInterceptor.class));
		if (!sameOriginDisabled()) {
			registration.setInterceptors(this.context.getBean(CsrfChannelInterceptor.class));
		}
		if (this.inboundRegistry.containsMapping()) {
			registration.setInterceptors(inboundChannelSecurity);
		}
		customizeClientInboundChannel(registration);
	}

	private PathMatcher getDefaultPathMatcher() {
		try {
			return this.context.getBean(SimpAnnotationMethodMessageHandler.class).getPathMatcher();
		}
		catch (NoSuchBeanDefinitionException e) {
			return new AntPathMatcher();
		}
	}

	/**
	 * <p>
	 * Determines if a CSRF token is required for connecting. This protects against remote
	 * sites from connecting to the application and being able to read/write data over the
	 * connection. The default is false (the token is required).
	 * </p>
	 * <p>
	 * Subclasses can override this method to disable CSRF protection
	 * </p>
	 * @return false if a CSRF token is required for connecting, else true
	 */
	protected boolean sameOriginDisabled() {
		return false;
	}

	/**
	 * Allows subclasses to customize the configuration of the {@link ChannelRegistration}
	 * .
	 * @param registration the {@link ChannelRegistration} to customize
	 */
	protected void customizeClientInboundChannel(ChannelRegistration registration) {
	}

	@Bean
	public CsrfChannelInterceptor csrfChannelInterceptor() {
		return new CsrfChannelInterceptor();
	}

	@Bean
	public ChannelSecurityInterceptor inboundChannelSecurity(
			MessageSecurityMetadataSource messageSecurityMetadataSource) {
		ChannelSecurityInterceptor channelSecurityInterceptor = new ChannelSecurityInterceptor(
				messageSecurityMetadataSource);
		MessageExpressionVoter<Object> voter = new MessageExpressionVoter<>();
		voter.setExpressionHandler(getMessageExpressionHandler());

		List<AccessDecisionVoter<?>> voters = new ArrayList<>();
		voters.add(voter);

		AffirmativeBased manager = new AffirmativeBased(voters);
		channelSecurityInterceptor.setAccessDecisionManager(manager);
		return channelSecurityInterceptor;
	}

	@Bean
	public SecurityContextChannelInterceptor securityContextChannelInterceptor() {
		return new SecurityContextChannelInterceptor();
	}

	@Bean
	public MessageSecurityMetadataSource inboundMessageSecurityMetadataSource() {
		this.inboundRegistry.expressionHandler(getMessageExpressionHandler());
		configureInbound(this.inboundRegistry);
		return this.inboundRegistry.createMetadataSource();
	}

	/**
	 * @param messages
	 */
	protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
	}

	private static class WebSocketMessageSecurityMetadataSourceRegistry extends MessageSecurityMetadataSourceRegistry {

		@Override
		public MessageSecurityMetadataSource createMetadataSource() {
			return super.createMetadataSource();
		}

		@Override
		protected boolean containsMapping() {
			return super.containsMapping();
		}

		@Override
		protected boolean isSimpDestPathMatcherConfigured() {
			return super.isSimpDestPathMatcherConfigured();
		}

	}

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.context = context;
	}

	@Deprecated
	public void setMessageExpessionHandler(List<SecurityExpressionHandler<Message<Object>>> expressionHandlers) {
		setMessageExpressionHandler(expressionHandlers);
	}

	@Autowired(required = false)
	public void setMessageExpressionHandler(List<SecurityExpressionHandler<Message<Object>>> expressionHandlers) {
		if (expressionHandlers.size() == 1) {
			this.expressionHandler = expressionHandlers.get(0);
		}
	}

	@Autowired(required = false)
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.defaultExpressionHandler = objectPostProcessor.postProcess(this.defaultExpressionHandler);
	}

	private SecurityExpressionHandler<Message<Object>> getMessageExpressionHandler() {
		if (this.expressionHandler == null) {
			return this.defaultExpressionHandler;
		}
		return this.expressionHandler;
	}

	@Override
	public void afterSingletonsInstantiated() {
		if (sameOriginDisabled()) {
			return;
		}

		String beanName = "stompWebSocketHandlerMapping";
		SimpleUrlHandlerMapping mapping = this.context.getBean(beanName, SimpleUrlHandlerMapping.class);
		Map<String, Object> mappings = mapping.getHandlerMap();
		for (Object object : mappings.values()) {
			if (object instanceof SockJsHttpRequestHandler) {
				SockJsHttpRequestHandler sockjsHandler = (SockJsHttpRequestHandler) object;
				SockJsService sockJsService = sockjsHandler.getSockJsService();
				if (!(sockJsService instanceof TransportHandlingSockJsService)) {
					throw new IllegalStateException(
							"sockJsService must be instance of TransportHandlingSockJsService got " + sockJsService);
				}

				TransportHandlingSockJsService transportHandlingSockJsService = (TransportHandlingSockJsService) sockJsService;
				List<HandshakeInterceptor> handshakeInterceptors = transportHandlingSockJsService
						.getHandshakeInterceptors();
				List<HandshakeInterceptor> interceptorsToSet = new ArrayList<>(handshakeInterceptors.size() + 1);
				interceptorsToSet.add(new CsrfTokenHandshakeInterceptor());
				interceptorsToSet.addAll(handshakeInterceptors);

				transportHandlingSockJsService.setHandshakeInterceptors(interceptorsToSet);
			}
			else if (object instanceof WebSocketHttpRequestHandler) {
				WebSocketHttpRequestHandler handler = (WebSocketHttpRequestHandler) object;
				List<HandshakeInterceptor> handshakeInterceptors = handler.getHandshakeInterceptors();
				List<HandshakeInterceptor> interceptorsToSet = new ArrayList<>(handshakeInterceptors.size() + 1);
				interceptorsToSet.add(new CsrfTokenHandshakeInterceptor());
				interceptorsToSet.addAll(handshakeInterceptors);

				handler.setHandshakeInterceptors(interceptorsToSet);
			}
			else {
				throw new IllegalStateException("Bean " + beanName
						+ " is expected to contain mappings to either a SockJsHttpRequestHandler or a WebSocketHttpRequestHandler but got "
						+ object);
			}
		}

		if (this.inboundRegistry.containsMapping() && !this.inboundRegistry.isSimpDestPathMatcherConfigured()) {
			PathMatcher pathMatcher = getDefaultPathMatcher();
			this.inboundRegistry.simpDestPathMatcher(pathMatcher);
		}
	}

}
