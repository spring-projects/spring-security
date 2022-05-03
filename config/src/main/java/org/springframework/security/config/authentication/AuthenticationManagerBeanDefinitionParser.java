/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.authentication;

import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.NamespaceHandlerResolver;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Registers the central ProviderManager used by the namespace configuration, and allows
 * the configuration of an alias, allowing users to reference it in their beans and
 * clearly see where the name is coming from.
 *
 * @author Luke Taylor
 */
public class AuthenticationManagerBeanDefinitionParser implements BeanDefinitionParser {

	private static final String ATT_ALIAS = "alias";

	private static final String ATT_REF = "ref";

	private static final String ATT_ERASE_CREDENTIALS = "erase-credentials";

	private static final String AUTHENTICATION_EVENT_PUBLISHER_BEAN_NAME = "defaultAuthenticationEventPublisher";

	@Override
	public BeanDefinition parse(Element element, ParserContext pc) {
		String id = element.getAttribute("id");
		if (!StringUtils.hasText(id)) {
			if (pc.getRegistry().containsBeanDefinition(BeanIds.AUTHENTICATION_MANAGER)) {
				pc.getReaderContext().warning("Overriding globally registered AuthenticationManager",
						pc.extractSource(element));
			}
			id = BeanIds.AUTHENTICATION_MANAGER;
		}
		pc.pushContainingComponent(new CompositeComponentDefinition(element.getTagName(), pc.extractSource(element)));
		BeanDefinitionBuilder providerManagerBldr = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);
		String alias = element.getAttribute(ATT_ALIAS);
		List<BeanMetadataElement> providers = new ManagedList<>();
		NamespaceHandlerResolver resolver = pc.getReaderContext().getNamespaceHandlerResolver();
		NodeList children = element.getChildNodes();
		for (int i = 0; i < children.getLength(); i++) {
			Node node = children.item(i);
			if (node instanceof Element) {
				providers.add(extracted(element, pc, resolver, (Element) node));
			}
		}
		if (providers.isEmpty()) {
			providers.add(new RootBeanDefinition(NullAuthenticationProvider.class));
		}
		providerManagerBldr.addConstructorArgValue(providers);
		if ("false".equals(element.getAttribute(ATT_ERASE_CREDENTIALS))) {
			providerManagerBldr.addPropertyValue("eraseCredentialsAfterAuthentication", false);
		}

		if (!pc.getRegistry().containsBeanDefinition(AUTHENTICATION_EVENT_PUBLISHER_BEAN_NAME)) {
			// Add the default event publisher to the context
			BeanDefinition publisher = new RootBeanDefinition(DefaultAuthenticationEventPublisher.class);
			pc.registerBeanComponent(new BeanComponentDefinition(publisher, AUTHENTICATION_EVENT_PUBLISHER_BEAN_NAME));
		}

		providerManagerBldr.addPropertyReference("authenticationEventPublisher",
				AUTHENTICATION_EVENT_PUBLISHER_BEAN_NAME);
		pc.registerBeanComponent(new BeanComponentDefinition(providerManagerBldr.getBeanDefinition(), id));
		if (StringUtils.hasText(alias)) {
			pc.getRegistry().registerAlias(id, alias);
			pc.getReaderContext().fireAliasRegistered(id, alias, pc.extractSource(element));
		}
		if (!BeanIds.AUTHENTICATION_MANAGER.equals(id)
				&& !pc.getRegistry().containsBeanDefinition(BeanIds.AUTHENTICATION_MANAGER)
				&& !pc.getRegistry().isAlias(BeanIds.AUTHENTICATION_MANAGER)) {
			pc.getRegistry().registerAlias(id, BeanIds.AUTHENTICATION_MANAGER);
			pc.getReaderContext().fireAliasRegistered(id, BeanIds.AUTHENTICATION_MANAGER, pc.extractSource(element));
		}
		pc.popAndRegisterContainingComponent();
		return null;
	}

	private BeanMetadataElement extracted(Element element, ParserContext pc, NamespaceHandlerResolver resolver,
			Element providerElement) {
		String ref = providerElement.getAttribute(ATT_REF);
		if (!StringUtils.hasText(ref)) {
			BeanDefinition provider = resolver.resolve(providerElement.getNamespaceURI()).parse(providerElement, pc);
			Assert.notNull(provider,
					() -> "Parser for " + providerElement.getNodeName() + " returned a null bean definition");
			String providerId = pc.getReaderContext().generateBeanName(provider);
			pc.registerBeanComponent(new BeanComponentDefinition(provider, providerId));
			return new RuntimeBeanReference(providerId);
		}
		if (providerElement.getAttributes().getLength() > 1) {
			pc.getReaderContext().error("authentication-provider element cannot be used with other attributes "
					+ "when using 'ref' attribute", pc.extractSource(element));
		}
		NodeList providerChildren = providerElement.getChildNodes();
		for (int i = 0; i < providerChildren.getLength(); i++) {
			if (providerChildren.item(i) instanceof Element) {
				pc.getReaderContext().error("authentication-provider element cannot have child elements when used "
						+ "with 'ref' attribute", pc.extractSource(element));
			}
		}
		return new RuntimeBeanReference(ref);
	}

	/**
	 * Provider which doesn't provide any service. Only used to prevent a configuration
	 * exception if the provider list is empty (usually because a child ProviderManager
	 * from the &lt;http&gt; namespace, such as OpenID, is expected to handle the
	 * request).
	 */
	public static final class NullAuthenticationProvider implements AuthenticationProvider {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return null;
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return false;
		}

	}

}
