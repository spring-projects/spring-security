/*
 * Copyright 2002-2012 the original author or authors.
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
package org.springframework.security.config.http;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.ListFactoryBean;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Elements;
import org.springframework.security.config.authentication.AuthenticationManagerFactoryBean;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.util.*;

/**
 * Sets up HTTP security: filter stack and protected URLs.
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @author Rob Winch
 * @since 2.0
 */
public class HttpSecurityBeanDefinitionParser implements BeanDefinitionParser {
	private static final Log logger = LogFactory
			.getLog(HttpSecurityBeanDefinitionParser.class);

	private static final String ATT_AUTHENTICATION_MANAGER_REF = "authentication-manager-ref";
	static final String ATT_REQUEST_MATCHER_REF = "request-matcher-ref";
	static final String ATT_PATH_PATTERN = "pattern";
	static final String ATT_HTTP_METHOD = "method";

	static final String ATT_FILTERS = "filters";
	static final String OPT_FILTERS_NONE = "none";

	static final String ATT_REQUIRES_CHANNEL = "requires-channel";

	private static final String ATT_REF = "ref";
	private static final String ATT_SECURED = "security";
	private static final String OPT_SECURITY_NONE = "none";

	public HttpSecurityBeanDefinitionParser() {
	}

	/**
	 * The aim of this method is to build the list of filters which have been defined by
	 * the namespace elements and attributes within the &lt;http&gt; configuration, along
	 * with any custom-filter's linked to user-defined filter beans.
	 * <p>
	 * By the end of this method, the default <tt>FilterChainProxy</tt> bean should have
	 * been registered and will have the map of filter chains defined, with the
	 * "universal" match pattern mapped to the list of beans which have been parsed here.
	 */
	@SuppressWarnings({ "unchecked" })
	@Override
	public BeanDefinition parse(Element element, ParserContext pc) {
		CompositeComponentDefinition compositeDef = new CompositeComponentDefinition(
				element.getTagName(), pc.extractSource(element));
		pc.pushContainingComponent(compositeDef);

		registerFilterChainProxyIfNecessary(pc, pc.extractSource(element));

		// Obtain the filter chains and add the new chain to it
		BeanDefinition listFactoryBean = pc.getRegistry().getBeanDefinition(
				BeanIds.FILTER_CHAINS);
		List<BeanReference> filterChains = (List<BeanReference>) listFactoryBean
				.getPropertyValues().getPropertyValue("sourceList").getValue();

		filterChains.add(createFilterChain(element, pc));

		pc.popAndRegisterContainingComponent();
		return null;
	}

	/**
	 * Creates the {@code SecurityFilterChain} bean from an &lt;http&gt; element.
	 */
	private BeanReference createFilterChain(Element element, ParserContext pc) {
		boolean secured = !OPT_SECURITY_NONE.equals(element.getAttribute(ATT_SECURED));

		if (!secured) {
			if (!StringUtils.hasText(element.getAttribute(ATT_PATH_PATTERN))
					&& !StringUtils.hasText(ATT_REQUEST_MATCHER_REF)) {
				pc.getReaderContext().error(
						"The '" + ATT_SECURED
								+ "' attribute must be used in combination with"
								+ " the '" + ATT_PATH_PATTERN + "' or '"
								+ ATT_REQUEST_MATCHER_REF + "' attributes.",
						pc.extractSource(element));
			}

			for (int n = 0; n < element.getChildNodes().getLength(); n++) {
				if (element.getChildNodes().item(n) instanceof Element) {
					pc.getReaderContext().error(
							"If you are using <http> to define an unsecured pattern, "
									+ "it cannot contain child elements.",
							pc.extractSource(element));
				}
			}

			return createSecurityFilterChainBean(element, pc, Collections.emptyList());
		}

		final BeanReference portMapper = createPortMapper(element, pc);
		final BeanReference portResolver = createPortResolver(portMapper, pc);

		ManagedList<BeanReference> authenticationProviders = new ManagedList<>();
		BeanReference authenticationManager = createAuthenticationManager(element, pc,
				authenticationProviders);

		boolean forceAutoConfig = isDefaultHttpConfig(element);
		HttpConfigurationBuilder httpBldr = new HttpConfigurationBuilder(element,
				forceAutoConfig, pc, portMapper, portResolver, authenticationManager);

		AuthenticationConfigBuilder authBldr = new AuthenticationConfigBuilder(element,
				forceAutoConfig, pc, httpBldr.getSessionCreationPolicy(),
				httpBldr.getRequestCache(), authenticationManager,
				httpBldr.getSessionStrategy(), portMapper, portResolver,
				httpBldr.getCsrfLogoutHandler());

		httpBldr.setLogoutHandlers(authBldr.getLogoutHandlers());
		httpBldr.setEntryPoint(authBldr.getEntryPointBean());
		httpBldr.setAccessDeniedHandler(authBldr.getAccessDeniedHandlerBean());

		authenticationProviders.addAll(authBldr.getProviders());

		List<OrderDecorator> unorderedFilterChain = new ArrayList<>();

		unorderedFilterChain.addAll(httpBldr.getFilters());
		unorderedFilterChain.addAll(authBldr.getFilters());
		unorderedFilterChain.addAll(buildCustomFilterList(element, pc));

		unorderedFilterChain.sort(new OrderComparator());
		checkFilterChainOrder(unorderedFilterChain, pc, pc.extractSource(element));

		// The list of filter beans
		List<BeanMetadataElement> filterChain = new ManagedList<>();

		for (OrderDecorator od : unorderedFilterChain) {
			filterChain.add(od.bean);
		}

		return createSecurityFilterChainBean(element, pc, filterChain);
	}

	private static boolean isDefaultHttpConfig(Element httpElt) {
		return httpElt.getChildNodes().getLength() == 0
				&& httpElt.getAttributes().getLength() == 0;
	}

	private BeanReference createSecurityFilterChainBean(Element element,
			ParserContext pc, List<?> filterChain) {
		BeanMetadataElement filterChainMatcher;

		String requestMatcherRef = element.getAttribute(ATT_REQUEST_MATCHER_REF);
		String filterChainPattern = element.getAttribute(ATT_PATH_PATTERN);

		if (StringUtils.hasText(requestMatcherRef)) {
			if (StringUtils.hasText(filterChainPattern)) {
				pc.getReaderContext().error(
						"You can't define a pattern and a request-matcher-ref for the "
								+ "same filter chain", pc.extractSource(element));
			}
			filterChainMatcher = new RuntimeBeanReference(requestMatcherRef);

		}
		else if (StringUtils.hasText(filterChainPattern)) {
			filterChainMatcher = MatcherType.fromElement(element).createMatcher(pc,
					filterChainPattern, null);
		}
		else {
			filterChainMatcher = new RootBeanDefinition(AnyRequestMatcher.class);
		}

		BeanDefinitionBuilder filterChainBldr = BeanDefinitionBuilder
				.rootBeanDefinition(DefaultSecurityFilterChain.class);
		filterChainBldr.addConstructorArgValue(filterChainMatcher);
		filterChainBldr.addConstructorArgValue(filterChain);

		BeanDefinition filterChainBean = filterChainBldr.getBeanDefinition();

		String id = element.getAttribute("name");
		if (!StringUtils.hasText(id)) {
			id = element.getAttribute("id");
			if (!StringUtils.hasText(id)) {
				id = pc.getReaderContext().generateBeanName(filterChainBean);
			}
		}

		pc.registerBeanComponent(new BeanComponentDefinition(filterChainBean, id));

		return new RuntimeBeanReference(id);
	}

	private BeanReference createPortMapper(Element elt, ParserContext pc) {
		// Register the portMapper. A default will always be created, even if no element
		// exists.
		BeanDefinition portMapper = new PortMappingsBeanDefinitionParser().parse(
				DomUtils.getChildElementByTagName(elt, Elements.PORT_MAPPINGS), pc);
		String portMapperName = pc.getReaderContext().generateBeanName(portMapper);
		pc.registerBeanComponent(new BeanComponentDefinition(portMapper, portMapperName));

		return new RuntimeBeanReference(portMapperName);
	}

	private RuntimeBeanReference createPortResolver(BeanReference portMapper,
			ParserContext pc) {
		RootBeanDefinition portResolver = new RootBeanDefinition(PortResolverImpl.class);
		portResolver.getPropertyValues().addPropertyValue("portMapper", portMapper);
		String portResolverName = pc.getReaderContext().generateBeanName(portResolver);
		pc.registerBeanComponent(new BeanComponentDefinition(portResolver,
				portResolverName));
		return new RuntimeBeanReference(portResolverName);
	}

	/**
	 * Creates the internal AuthenticationManager bean which uses either the externally
	 * registered (global) one as a parent or the bean specified by
	 * "authentication-manager-ref".
	 *
	 * All the providers registered by this &lt;http&gt; block will be registered with the
	 * internal authentication manager.
	 */
	private BeanReference createAuthenticationManager(Element element, ParserContext pc,
			ManagedList<BeanReference> authenticationProviders) {
		String parentMgrRef = element.getAttribute(ATT_AUTHENTICATION_MANAGER_REF);
		BeanDefinitionBuilder authManager = BeanDefinitionBuilder
				.rootBeanDefinition(ProviderManager.class);
		authManager.addConstructorArgValue(authenticationProviders);

		if (StringUtils.hasText(parentMgrRef)) {
			RuntimeBeanReference parentAuthManager = new RuntimeBeanReference(
					parentMgrRef);
			authManager.addConstructorArgValue(parentAuthManager);
			RootBeanDefinition clearCredentials = new RootBeanDefinition(
					ClearCredentialsMethodInvokingFactoryBean.class);
			clearCredentials.getPropertyValues().addPropertyValue("targetObject",
					parentAuthManager);
			clearCredentials.getPropertyValues().addPropertyValue("targetMethod",
					"isEraseCredentialsAfterAuthentication");

			authManager.addPropertyValue("eraseCredentialsAfterAuthentication",
					clearCredentials);
		}
		else {
			RootBeanDefinition amfb = new RootBeanDefinition(
					AuthenticationManagerFactoryBean.class);
			amfb.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
			String amfbId = pc.getReaderContext().generateBeanName(amfb);
			pc.registerBeanComponent(new BeanComponentDefinition(amfb, amfbId));
			RootBeanDefinition clearCredentials = new RootBeanDefinition(
					MethodInvokingFactoryBean.class);
			clearCredentials.getPropertyValues().addPropertyValue("targetObject",
					new RuntimeBeanReference(amfbId));
			clearCredentials.getPropertyValues().addPropertyValue("targetMethod",
					"isEraseCredentialsAfterAuthentication");

			authManager.addConstructorArgValue(new RuntimeBeanReference(amfbId));
			authManager.addPropertyValue("eraseCredentialsAfterAuthentication",
					clearCredentials);
		}

		authManager.getRawBeanDefinition().setSource(pc.extractSource(element));
		BeanDefinition authMgrBean = authManager.getBeanDefinition();
		String id = pc.getReaderContext().generateBeanName(authMgrBean);
		pc.registerBeanComponent(new BeanComponentDefinition(authMgrBean, id));

		return new RuntimeBeanReference(id);
	}

	private void checkFilterChainOrder(List<OrderDecorator> filters, ParserContext pc,
			Object source) {
		logger.info("Checking sorted filter chain: " + filters);

		for (int i = 0; i < filters.size(); i++) {
			OrderDecorator filter = filters.get(i);

			if (i > 0) {
				OrderDecorator previous = filters.get(i - 1);
				if (filter.getOrder() == previous.getOrder()) {
					pc.getReaderContext()
							.error("Filter beans '"
									+ filter.bean
									+ "' and '"
									+ previous.bean
									+ "' have the same 'order' value. When using custom filters, "
									+ "please make sure the positions do not conflict with default filters. "
									+ "Alternatively you can disable the default filters by removing the corresponding "
									+ "child elements from <http> and avoiding the use of <http auto-config='true'>.",
									source);
				}
			}
		}
	}

	List<OrderDecorator> buildCustomFilterList(Element element, ParserContext pc) {
		List<Element> customFilterElts = DomUtils.getChildElementsByTagName(element,
				Elements.CUSTOM_FILTER);
		List<OrderDecorator> customFilters = new ArrayList<>();

		final String ATT_AFTER = "after";
		final String ATT_BEFORE = "before";
		final String ATT_POSITION = "position";

		for (Element elt : customFilterElts) {
			String after = elt.getAttribute(ATT_AFTER);
			String before = elt.getAttribute(ATT_BEFORE);
			String position = elt.getAttribute(ATT_POSITION);

			String ref = elt.getAttribute(ATT_REF);

			if (!StringUtils.hasText(ref)) {
				pc.getReaderContext().error(
						"The '" + ATT_REF + "' attribute must be supplied",
						pc.extractSource(elt));
			}

			RuntimeBeanReference bean = new RuntimeBeanReference(ref);

			if (WebConfigUtils.countNonEmpty(new String[] { after, before, position }) != 1) {
				pc.getReaderContext().error(
						"A single '" + ATT_AFTER + "', '" + ATT_BEFORE + "', or '"
								+ ATT_POSITION + "' attribute must be supplied",
						pc.extractSource(elt));
			}

			if (StringUtils.hasText(position)) {
				customFilters.add(new OrderDecorator(bean, SecurityFilters
						.valueOf(position)));
			}
			else if (StringUtils.hasText(after)) {
				SecurityFilters order = SecurityFilters.valueOf(after);
				if (order == SecurityFilters.LAST) {
					customFilters.add(new OrderDecorator(bean, SecurityFilters.LAST));
				}
				else {
					customFilters.add(new OrderDecorator(bean, order.getOrder() + 1));
				}
			}
			else if (StringUtils.hasText(before)) {
				SecurityFilters order = SecurityFilters.valueOf(before);
				if (order == SecurityFilters.FIRST) {
					customFilters.add(new OrderDecorator(bean, SecurityFilters.FIRST));
				}
				else {
					customFilters.add(new OrderDecorator(bean, order.getOrder() - 1));
				}
			}
		}

		return customFilters;
	}

	static void registerFilterChainProxyIfNecessary(ParserContext pc, Object source) {
		if (pc.getRegistry().containsBeanDefinition(BeanIds.FILTER_CHAIN_PROXY)) {
			return;
		}
		// Not already registered, so register the list of filter chains and the
		// FilterChainProxy
		BeanDefinition listFactoryBean = new RootBeanDefinition(ListFactoryBean.class);
		listFactoryBean.getPropertyValues().add("sourceList", new ManagedList());
		pc.registerBeanComponent(new BeanComponentDefinition(listFactoryBean,
				BeanIds.FILTER_CHAINS));

		BeanDefinitionBuilder fcpBldr = BeanDefinitionBuilder
				.rootBeanDefinition(FilterChainProxy.class);
		fcpBldr.getRawBeanDefinition().setSource(source);
		fcpBldr.addConstructorArgReference(BeanIds.FILTER_CHAINS);
		fcpBldr.addPropertyValue("filterChainValidator", new RootBeanDefinition(
				DefaultFilterChainValidator.class));
		BeanDefinition fcpBean = fcpBldr.getBeanDefinition();
		pc.registerBeanComponent(new BeanComponentDefinition(fcpBean,
				BeanIds.FILTER_CHAIN_PROXY));
		pc.getRegistry().registerAlias(BeanIds.FILTER_CHAIN_PROXY,
				BeanIds.SPRING_SECURITY_FILTER_CHAIN);
	}

}

class OrderDecorator implements Ordered {
	final BeanMetadataElement bean;
	final int order;

	OrderDecorator(BeanMetadataElement bean, SecurityFilters filterOrder) {
		this.bean = bean;
		this.order = filterOrder.getOrder();
	}

	OrderDecorator(BeanMetadataElement bean, int order) {
		this.bean = bean;
		this.order = order;
	}

	@Override
	public int getOrder() {
		return order;
	}

	@Override
	public String toString() {
		return bean + ", order = " + order;
	}
}

/**
 * Custom {@link MethodInvokingFactoryBean} that is specifically used for looking up the
 * child {@link ProviderManager} value for
 * {@link ProviderManager#setEraseCredentialsAfterAuthentication(boolean)} given the
 * parent {@link AuthenticationManager}. This is necessary because the parent
 * {@link AuthenticationManager} might not be a {@link ProviderManager}.
 *
 * @author Rob Winch
 */
final class ClearCredentialsMethodInvokingFactoryBean extends MethodInvokingFactoryBean {
	@Override
	public void afterPropertiesSet() throws Exception {
		boolean isTargetProviderManager = getTargetObject() instanceof ProviderManager;
		if (!isTargetProviderManager) {
			setTargetObject(this);
		}
		super.afterPropertiesSet();
	}

	/**
	 * The default value if the target object is not a ProviderManager is false. We use
	 * false because this feature is associated with {@link ProviderManager} not
	 * {@link AuthenticationManager}. If the user wants to leverage
	 * {@link ProviderManager#setEraseCredentialsAfterAuthentication(boolean)} their
	 * original {@link AuthenticationManager} must be a {@link ProviderManager} (we should
	 * not magically add this functionality to their implementation since we cannot
	 * determine if it should be on or off).
	 *
	 * @return
	 */
	public boolean isEraseCredentialsAfterAuthentication() {
		return false;
	}
}
