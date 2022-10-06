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

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.w3c.dom.Element;

import org.springframework.beans.BeansException;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.XmlReaderContext;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.simp.annotation.support.SimpAnnotationMethodMessageHandler;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.ConsensusBased;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Elements;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.messaging.access.expression.ExpressionBasedMessageSecurityMetadataSourceFactory;
import org.springframework.security.messaging.access.expression.MessageAuthorizationContextSecurityExpressionHandler;
import org.springframework.security.messaging.access.expression.MessageExpressionVoter;
import org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor;
import org.springframework.security.messaging.access.intercept.ChannelSecurityInterceptor;
import org.springframework.security.messaging.access.intercept.MessageAuthorizationContext;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.messaging.context.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.security.messaging.util.matcher.SimpDestinationMessageMatcher;
import org.springframework.security.messaging.util.matcher.SimpMessageTypeMatcher;
import org.springframework.security.messaging.web.csrf.CsrfChannelInterceptor;
import org.springframework.security.messaging.web.socket.server.CsrfTokenHandshakeInterceptor;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.PathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * Parses Spring Security's websocket namespace support. A simple example is:
 *
 * <code>
 * &lt;websocket-message-broker&gt;
 *     &lt;intercept-message pattern='/permitAll' access='permitAll' /&gt;
 *     &lt;intercept-message pattern='/denyAll' access='denyAll' /&gt;
 * &lt;/websocket-message-broker&gt;
 * </code>
 *
 * <p>
 * The above configuration will ensure that any SimpAnnotationMethodMessageHandler has the
 * AuthenticationPrincipalArgumentResolver registered as a custom argument resolver. It
 * also ensures that the SecurityContextChannelInterceptor is automatically registered for
 * the clientInboundChannel. Last, it ensures that a ChannelSecurityInterceptor is
 * registered with the clientInboundChannel.
 * </p>
 *
 * <p>
 * If finer control is necessary, the id attribute can be used as shown below:
 * </p>
 *
 * <code>
 * &lt;websocket-message-broker id="channelSecurityInterceptor"&gt;
 *     &lt;intercept-message pattern='/permitAll' access='permitAll' /&gt;
 *     &lt;intercept-message pattern='/denyAll' access='denyAll' /&gt;
 * &lt;/websocket-message-broker&gt;
 * </code>
 *
 * <p>
 * Now the configuration will only create a bean named ChannelSecurityInterceptor and
 * assign it to the id of channelSecurityInterceptor. Users can explicitly wire Spring
 * Security using the standard Spring Messaging XML namespace support.
 * </p>
 *
 * @author Rob Winch
 * @since 4.0
 */
public final class WebSocketMessageBrokerSecurityBeanDefinitionParser implements BeanDefinitionParser {

	private static final String ID_ATTR = "id";

	private static final String DISABLED_ATTR = "same-origin-disabled";

	private static final String USE_AUTHORIZATION_MANAGER_ATTR = "use-authorization-manager";

	private static final String AUTHORIZATION_MANAGER_REF_ATTR = "authorization-manager-ref";

	private static final String SECURITY_CONTEXT_HOLDER_STRATEGY_REF_ATTR = "security-context-holder-strategy-ref";

	private static final String PATTERN_ATTR = "pattern";

	private static final String ACCESS_ATTR = "access";

	private static final String TYPE_ATTR = "type";

	private static final String PATH_MATCHER_BEAN_NAME = "springSecurityMessagePathMatcher";

	/**
	 * @param element
	 * @param parserContext
	 * @return the {@link BeanDefinition}
	 */
	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		String id = element.getAttribute(ID_ATTR);
		String inSecurityInterceptorName = parseAuthorization(element, parserContext);
		BeanDefinitionRegistry registry = parserContext.getRegistry();
		if (StringUtils.hasText(id)) {
			registry.registerAlias(inSecurityInterceptorName, id);
			if (!registry.containsBeanDefinition(PATH_MATCHER_BEAN_NAME)) {
				registry.registerBeanDefinition(PATH_MATCHER_BEAN_NAME, new RootBeanDefinition(AntPathMatcher.class));
			}
		}
		else {
			boolean sameOriginDisabled = Boolean.parseBoolean(element.getAttribute(DISABLED_ATTR));
			XmlReaderContext context = parserContext.getReaderContext();
			BeanDefinitionBuilder mspp = BeanDefinitionBuilder.rootBeanDefinition(MessageSecurityPostProcessor.class);
			mspp.addConstructorArgValue(inSecurityInterceptorName);
			mspp.addConstructorArgValue(sameOriginDisabled);
			context.registerWithGeneratedName(mspp.getBeanDefinition());
		}
		return null;
	}

	private String parseAuthorization(Element element, ParserContext parserContext) {
		boolean useAuthorizationManager = true;
		if (StringUtils.hasText(element.getAttribute(USE_AUTHORIZATION_MANAGER_ATTR))) {
			useAuthorizationManager = Boolean.parseBoolean(element.getAttribute(USE_AUTHORIZATION_MANAGER_ATTR));
		}
		if (useAuthorizationManager) {
			return parseAuthorizationManager(element, parserContext);
		}
		if (StringUtils.hasText(element.getAttribute(AUTHORIZATION_MANAGER_REF_ATTR))) {
			return parseAuthorizationManager(element, parserContext);
		}
		return parseSecurityMetadataSource(element, parserContext);
	}

	private String parseAuthorizationManager(Element element, ParserContext parserContext) {
		XmlReaderContext context = parserContext.getReaderContext();
		String mdsId = createAuthorizationManager(element, parserContext);
		BeanDefinitionBuilder inboundChannelSecurityInterceptor = BeanDefinitionBuilder
				.rootBeanDefinition(AuthorizationChannelInterceptor.class);
		inboundChannelSecurityInterceptor.addConstructorArgReference(mdsId);
		String holderStrategyRef = element.getAttribute(SECURITY_CONTEXT_HOLDER_STRATEGY_REF_ATTR);
		if (StringUtils.hasText(holderStrategyRef)) {
			inboundChannelSecurityInterceptor.addPropertyValue("securityContextHolderStrategy",
					new RuntimeBeanReference(holderStrategyRef));
		}
		else {
			inboundChannelSecurityInterceptor.addPropertyValue("securityContextHolderStrategy", BeanDefinitionBuilder
					.rootBeanDefinition(SecurityContextHolderStrategyFactory.class).getBeanDefinition());
		}

		return context.registerWithGeneratedName(inboundChannelSecurityInterceptor.getBeanDefinition());
	}

	private String createAuthorizationManager(Element element, ParserContext parserContext) {
		XmlReaderContext context = parserContext.getReaderContext();
		String authorizationManagerRef = element.getAttribute(AUTHORIZATION_MANAGER_REF_ATTR);
		if (StringUtils.hasText(authorizationManagerRef)) {
			return authorizationManagerRef;
		}
		Element expressionHandlerElt = DomUtils.getChildElementByTagName(element, Elements.EXPRESSION_HANDLER);
		String expressionHandlerRef = (expressionHandlerElt != null) ? expressionHandlerElt.getAttribute("ref") : null;
		ManagedMap<BeanDefinition, BeanDefinition> matcherToExpression = new ManagedMap<>();
		List<Element> interceptMessages = DomUtils.getChildElementsByTagName(element, Elements.INTERCEPT_MESSAGE);
		for (Element interceptMessage : interceptMessages) {
			String matcherPattern = interceptMessage.getAttribute(PATTERN_ATTR);
			String accessExpression = interceptMessage.getAttribute(ACCESS_ATTR);
			String messageType = interceptMessage.getAttribute(TYPE_ATTR);
			BeanDefinition matcher = createMatcher(matcherPattern, messageType, parserContext, interceptMessage);
			BeanDefinitionBuilder authorizationManager = BeanDefinitionBuilder
					.rootBeanDefinition(ExpressionBasedAuthorizationManager.class);
			if (StringUtils.hasText(expressionHandlerRef)) {
				authorizationManager.addConstructorArgReference(expressionHandlerRef);
			}
			authorizationManager.addConstructorArgValue(accessExpression);
			matcherToExpression.put(matcher, authorizationManager.getBeanDefinition());
		}
		BeanDefinitionBuilder mds = BeanDefinitionBuilder
				.rootBeanDefinition(MessageMatcherDelegatingAuthorizationManagerFactory.class);
		mds.setFactoryMethod("createMessageMatcherDelegatingAuthorizationManager");
		mds.addConstructorArgValue(matcherToExpression);
		return context.registerWithGeneratedName(mds.getBeanDefinition());
	}

	private String parseSecurityMetadataSource(Element element, ParserContext parserContext) {
		BeanDefinitionRegistry registry = parserContext.getRegistry();
		XmlReaderContext context = parserContext.getReaderContext();
		ManagedMap<BeanDefinition, String> matcherToExpression = new ManagedMap<>();
		Element expressionHandlerElt = DomUtils.getChildElementByTagName(element, Elements.EXPRESSION_HANDLER);
		String expressionHandlerRef = (expressionHandlerElt != null) ? expressionHandlerElt.getAttribute("ref") : null;
		boolean expressionHandlerDefined = StringUtils.hasText(expressionHandlerRef);
		List<Element> interceptMessages = DomUtils.getChildElementsByTagName(element, Elements.INTERCEPT_MESSAGE);
		for (Element interceptMessage : interceptMessages) {
			String matcherPattern = interceptMessage.getAttribute(PATTERN_ATTR);
			String accessExpression = interceptMessage.getAttribute(ACCESS_ATTR);
			String messageType = interceptMessage.getAttribute(TYPE_ATTR);
			BeanDefinition matcher = createMatcher(matcherPattern, messageType, parserContext, interceptMessage);
			matcherToExpression.put(matcher, accessExpression);
		}
		BeanDefinitionBuilder mds = BeanDefinitionBuilder
				.rootBeanDefinition(ExpressionBasedMessageSecurityMetadataSourceFactory.class);
		mds.setFactoryMethod("createExpressionMessageMetadataSource");
		mds.addConstructorArgValue(matcherToExpression);
		if (expressionHandlerDefined) {
			mds.addConstructorArgReference(expressionHandlerRef);
		}
		String mdsId = context.registerWithGeneratedName(mds.getBeanDefinition());
		ManagedList<BeanDefinition> voters = new ManagedList<>();
		BeanDefinitionBuilder messageExpressionVoterBldr = BeanDefinitionBuilder
				.rootBeanDefinition(MessageExpressionVoter.class);
		if (expressionHandlerDefined) {
			messageExpressionVoterBldr.addPropertyReference("expressionHandler", expressionHandlerRef);
		}
		voters.add(messageExpressionVoterBldr.getBeanDefinition());
		BeanDefinitionBuilder adm = BeanDefinitionBuilder.rootBeanDefinition(ConsensusBased.class);
		adm.addConstructorArgValue(voters);
		BeanDefinitionBuilder inboundChannelSecurityInterceptor = BeanDefinitionBuilder
				.rootBeanDefinition(ChannelSecurityInterceptor.class);
		inboundChannelSecurityInterceptor.addConstructorArgValue(registry.getBeanDefinition(mdsId));
		inboundChannelSecurityInterceptor.addPropertyValue("accessDecisionManager", adm.getBeanDefinition());
		return context.registerWithGeneratedName(inboundChannelSecurityInterceptor.getBeanDefinition());
	}

	private BeanDefinition createMatcher(String matcherPattern, String messageType, ParserContext parserContext,
			Element interceptMessage) {
		boolean hasPattern = StringUtils.hasText(matcherPattern);
		boolean hasMessageType = StringUtils.hasText(messageType);
		if (!hasPattern) {
			BeanDefinitionBuilder matcher = BeanDefinitionBuilder.rootBeanDefinition(SimpMessageTypeMatcher.class);
			matcher.addConstructorArgValue(messageType);
			return matcher.getBeanDefinition();
		}
		String factoryName = null;
		if (hasPattern && hasMessageType) {
			SimpMessageType type = SimpMessageType.valueOf(messageType);
			if (SimpMessageType.MESSAGE == type) {
				factoryName = "createMessageMatcher";
			}
			else if (SimpMessageType.SUBSCRIBE == type) {
				factoryName = "createSubscribeMatcher";
			}
			else {
				parserContext.getReaderContext().error("Cannot use intercept-websocket@message-type=" + messageType
						+ " with a pattern because the type does not have a destination.", interceptMessage);
			}
		}
		BeanDefinitionBuilder matcher = BeanDefinitionBuilder.rootBeanDefinition(SimpDestinationMessageMatcher.class);
		matcher.setFactoryMethod(factoryName);
		matcher.addConstructorArgValue(matcherPattern);
		matcher.addConstructorArgValue(new RuntimeBeanReference("springSecurityMessagePathMatcher"));
		return matcher.getBeanDefinition();
	}

	static class MessageSecurityPostProcessor implements BeanDefinitionRegistryPostProcessor {

		/**
		 * This is not available prior to Spring 4.2
		 */
		private static final String WEB_SOCKET_AMMH_CLASS_NAME = "org.springframework.web.socket.messaging.WebSocketAnnotationMethodMessageHandler";

		private static final String CLIENT_INBOUND_CHANNEL_BEAN_ID = "clientInboundChannel";

		private static final String INTERCEPTORS_PROP = "interceptors";

		private static final String CUSTOM_ARG_RESOLVERS_PROP = "customArgumentResolvers";

		private final String inboundSecurityInterceptorId;

		private final boolean sameOriginDisabled;

		MessageSecurityPostProcessor(String inboundSecurityInterceptorId, boolean sameOriginDisabled) {
			this.inboundSecurityInterceptorId = inboundSecurityInterceptorId;
			this.sameOriginDisabled = sameOriginDisabled;
		}

		@Override
		public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
			String[] beanNames = registry.getBeanDefinitionNames();
			for (String beanName : beanNames) {
				BeanDefinition bd = registry.getBeanDefinition(beanName);
				String beanClassName = bd.getBeanClassName();
				if (SimpAnnotationMethodMessageHandler.class.getName().equals(beanClassName)
						|| WEB_SOCKET_AMMH_CLASS_NAME.equals(beanClassName)) {
					PropertyValue current = bd.getPropertyValues().getPropertyValue(CUSTOM_ARG_RESOLVERS_PROP);
					ManagedList<Object> argResolvers = new ManagedList<>();
					if (current != null) {
						argResolvers.addAll((ManagedList<?>) current.getValue());
					}
					argResolvers.add(new RootBeanDefinition(AuthenticationPrincipalArgumentResolver.class));
					bd.getPropertyValues().add(CUSTOM_ARG_RESOLVERS_PROP, argResolvers);
					if (!registry.containsBeanDefinition(PATH_MATCHER_BEAN_NAME)) {
						PropertyValue pathMatcherProp = bd.getPropertyValues().getPropertyValue("pathMatcher");
						Object pathMatcher = (pathMatcherProp != null) ? pathMatcherProp.getValue() : null;
						if (pathMatcher instanceof BeanReference) {
							registry.registerAlias(((BeanReference) pathMatcher).getBeanName(), PATH_MATCHER_BEAN_NAME);
						}
					}
				}
				else if ("org.springframework.web.socket.server.support.WebSocketHttpRequestHandler"
						.equals(beanClassName)) {
					addCsrfTokenHandshakeInterceptor(bd);
				}
				else if ("org.springframework.web.socket.sockjs.transport.TransportHandlingSockJsService"
						.equals(beanClassName)) {
					addCsrfTokenHandshakeInterceptor(bd);
				}
				else if ("org.springframework.web.socket.sockjs.transport.handler.DefaultSockJsService"
						.equals(beanClassName)) {
					addCsrfTokenHandshakeInterceptor(bd);
				}
			}
			if (!registry.containsBeanDefinition(CLIENT_INBOUND_CHANNEL_BEAN_ID)) {
				return;
			}
			ManagedList<Object> interceptors = new ManagedList();
			interceptors.add(new RootBeanDefinition(SecurityContextChannelInterceptor.class));
			if (!this.sameOriginDisabled) {
				interceptors.add(new RootBeanDefinition(CsrfChannelInterceptor.class));
			}
			interceptors.add(registry.getBeanDefinition(this.inboundSecurityInterceptorId));
			BeanDefinition inboundChannel = registry.getBeanDefinition(CLIENT_INBOUND_CHANNEL_BEAN_ID);
			PropertyValue currentInterceptorsPv = inboundChannel.getPropertyValues()
					.getPropertyValue(INTERCEPTORS_PROP);
			if (currentInterceptorsPv != null) {
				ManagedList<?> currentInterceptors = (ManagedList<?>) currentInterceptorsPv.getValue();
				interceptors.addAll(currentInterceptors);
			}
			inboundChannel.getPropertyValues().add(INTERCEPTORS_PROP, interceptors);
			if (!registry.containsBeanDefinition(PATH_MATCHER_BEAN_NAME)) {
				registry.registerBeanDefinition(PATH_MATCHER_BEAN_NAME, new RootBeanDefinition(AntPathMatcher.class));
			}
		}

		private void addCsrfTokenHandshakeInterceptor(BeanDefinition bd) {
			if (this.sameOriginDisabled) {
				return;
			}
			String interceptorPropertyName = "handshakeInterceptors";
			ManagedList<? super Object> interceptors = new ManagedList<>();
			interceptors.add(new RootBeanDefinition(CsrfTokenHandshakeInterceptor.class));
			interceptors.addAll((ManagedList<Object>) bd.getPropertyValues().get(interceptorPropertyName));
			bd.getPropertyValues().add(interceptorPropertyName, interceptors);
		}

		@Override
		public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

		}

	}

	static class DelegatingPathMatcher implements PathMatcher {

		private PathMatcher delegate = new AntPathMatcher();

		@Override
		public boolean isPattern(String path) {
			return this.delegate.isPattern(path);
		}

		@Override
		public boolean match(String pattern, String path) {
			return this.delegate.match(pattern, path);
		}

		@Override
		public boolean matchStart(String pattern, String path) {
			return this.delegate.matchStart(pattern, path);
		}

		@Override
		public String extractPathWithinPattern(String pattern, String path) {
			return this.delegate.extractPathWithinPattern(pattern, path);
		}

		@Override
		public Map<String, String> extractUriTemplateVariables(String pattern, String path) {
			return this.delegate.extractUriTemplateVariables(pattern, path);
		}

		@Override
		public Comparator<String> getPatternComparator(String path) {
			return this.delegate.getPatternComparator(path);
		}

		@Override
		public String combine(String pattern1, String pattern2) {
			return this.delegate.combine(pattern1, pattern2);
		}

		void setPathMatcher(PathMatcher pathMatcher) {
			this.delegate = pathMatcher;
		}

	}

	private static final class ExpressionBasedAuthorizationManager
			implements AuthorizationManager<MessageAuthorizationContext<?>> {

		private final SecurityExpressionHandler<MessageAuthorizationContext<?>> expressionHandler;

		private final Expression expression;

		private ExpressionBasedAuthorizationManager(String expression) {
			this(new MessageAuthorizationContextSecurityExpressionHandler(), expression);
		}

		private ExpressionBasedAuthorizationManager(
				SecurityExpressionHandler<MessageAuthorizationContext<?>> expressionHandler, String expression) {
			Assert.notNull(expressionHandler, "expressionHandler cannot be null");
			Assert.notNull(expression, "expression cannot be null");
			this.expressionHandler = expressionHandler;
			this.expression = this.expressionHandler.getExpressionParser().parseExpression(expression);
		}

		@Override
		public AuthorizationDecision check(Supplier<Authentication> authentication,
				MessageAuthorizationContext<?> object) {
			EvaluationContext context = this.expressionHandler.createEvaluationContext(authentication, object);
			boolean granted = ExpressionUtils.evaluateAsBoolean(this.expression, context);
			return new AuthorizationDecision(granted);
		}

	}

	private static class MessageMatcherDelegatingAuthorizationManagerFactory {

		private static AuthorizationManager<Message<?>> createMessageMatcherDelegatingAuthorizationManager(
				Map<MessageMatcher<?>, AuthorizationManager<MessageAuthorizationContext<?>>> beans) {
			MessageMatcherDelegatingAuthorizationManager.Builder builder = MessageMatcherDelegatingAuthorizationManager
					.builder();
			for (Map.Entry<MessageMatcher<?>, AuthorizationManager<MessageAuthorizationContext<?>>> entry : beans
					.entrySet()) {
				builder.matchers(entry.getKey()).access(entry.getValue());
			}
			return builder.anyMessage().permitAll().build();
		}

	}

	static class SecurityContextHolderStrategyFactory implements FactoryBean<SecurityContextHolderStrategy> {

		@Override
		public SecurityContextHolderStrategy getObject() throws Exception {
			return SecurityContextHolder.getContextHolderStrategy();
		}

		@Override
		public Class<?> getObjectType() {
			return SecurityContextHolderStrategy.class;
		}

	}

}
