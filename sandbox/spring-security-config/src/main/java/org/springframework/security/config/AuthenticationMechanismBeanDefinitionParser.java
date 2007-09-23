/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config;

import org.springframework.security.ldap.DefaultInitialDirContextFactory;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.ldap.LdapAuthenticationProvider;
import org.springframework.security.providers.ldap.authenticator.BindAuthenticator;
import org.springframework.security.providers.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.util.BeanDefinitionParserUtils;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * * {@link BeanDefinitionParser} for the <code>authentication-mechanism</code>
 * tag, resolves to {@link org.springframework.security.providers.ProviderManager} </br>
 * 
 * @author vpuri
 * @see {@link org.springframework.beans.factory.BeanFactory}
 * @see {@link org.springframework.security.providers.ProviderManager}
 * 
 */
public class AuthenticationMechanismBeanDefinitionParser extends AbstractBeanDefinitionParser implements
		BeanDefinitionParser {
	// ~ Instance fields
	// ================================================================================================

	private static final String AUTHENTICATION_JDBC = "authentication-jdbc";

	private static final String AUTHENTICATION_LDAP = "authentication-ldap";

	private static final String REF = "ref";

	// ~ Methods
	// ========================================================================================================
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		ManagedList providers = new ManagedList();
		Assert.notNull(parserContext, "ParserContext must not be null");
		RootBeanDefinition authMechanismBeanDef = new RootBeanDefinition(ProviderManager.class);
		NodeList childNodes = element.getChildNodes();

		for (int i = 0, n = childNodes.getLength(); i < n; i++) {
			Node node = childNodes.item(i);

			if (node.getNodeType() == Node.ELEMENT_NODE) {
				Element childElement = (Element) node;
				// this.providerExists = true;

				if (AUTHENTICATION_JDBC.equals(node.getLocalName())) {
					String attribute = childElement.getAttribute(REF);
					if (StringUtils.hasLength(attribute)) {
						// create a beandefinition
						providers.add(new RuntimeBeanReference(attribute));
					}
				}
				else if (AUTHENTICATION_LDAP.equals(node.getLocalName())) {
					providers.add(createLdapAuthencticationProviderBeanDefinition(childElement, parserContext));
				}
			}
			authMechanismBeanDef.getPropertyValues().addPropertyValue("providers", providers);

		}
		return authMechanismBeanDef;
	}

	/**
	 * Creates a default bean definition.
	 * @return
	 */
	protected static RootBeanDefinition createAndRegisterBeanDefinitionWithDefaults(ParserContext parserContext) {
		RootBeanDefinition beanDefinition = new RootBeanDefinition(ProviderManager.class);
		ManagedList providers = new ManagedList();
		// create authentication-repository (DaoAuthenticationProvider) and add
		// that to list
		RootBeanDefinition authRepo = AuthenticationRepositoryBeanDefinitionParser.createBeanDefinitionWithDefaults();
		providers.add(authRepo);
		beanDefinition.getPropertyValues().addPropertyValue("providers", providers);
		parserContext.getReaderContext().registerWithGeneratedName(beanDefinition);
		return beanDefinition;
	}

	protected static RootBeanDefinition createLdapAuthencticationProviderBeanDefinition(Element element,
			ParserContext parserContext) {
		// element ldap
		RootBeanDefinition ldapAuthProvider = new RootBeanDefinition(LdapAuthenticationProvider.class);
		RootBeanDefinition initialDirContextFactory = createInitialDirContextFactoryBeanDefinition(element);
		RootBeanDefinition ldapAuthoritiesPopulator = new RootBeanDefinition(DefaultLdapAuthoritiesPopulator.class);

		RootBeanDefinition bindAuthenticator = new RootBeanDefinition(BindAuthenticator.class);
		Element property = DomUtils.getChildElementByTagName(element, "property");
		Assert.notNull(property);
		parserContext.getDelegate().parsePropertyElement(property, bindAuthenticator);
		bindAuthenticator.getConstructorArgumentValues().addIndexedArgumentValue(0, initialDirContextFactory);

		// LdapAuthenticator
		ldapAuthProvider.getConstructorArgumentValues().addIndexedArgumentValue(0, bindAuthenticator);

		ldapAuthoritiesPopulator.getConstructorArgumentValues().addIndexedArgumentValue(0, initialDirContextFactory);
		BeanDefinitionParserUtils.setConstructorArgumentIfAvailable(1, element, "groupSearchBase", false,
				ldapAuthoritiesPopulator);
		BeanDefinitionParserUtils.setPropertyIfAvailable(element, "groupRoleAttribute", "groupRoleAttribute", false,
				ldapAuthoritiesPopulator);

		// LdapAuthoritiesPopulator
		ldapAuthProvider.getConstructorArgumentValues().addIndexedArgumentValue(1, ldapAuthoritiesPopulator);

		return ldapAuthProvider;

	}

	private static RootBeanDefinition createInitialDirContextFactoryBeanDefinition(Element element) {
		RootBeanDefinition initialDirContextFactory = new RootBeanDefinition(DefaultInitialDirContextFactory.class);
		BeanDefinitionParserUtils.setConstructorArgumentIfAvailable(0, element, "ldapUrl", false,
				initialDirContextFactory);
		BeanDefinitionParserUtils.setPropertyIfAvailable(element, "managerDn", "managerDn", false,
				initialDirContextFactory);
		BeanDefinitionParserUtils.setPropertyIfAvailable(element, "managerPassword", "managerPassword", false,
				initialDirContextFactory);
		return initialDirContextFactory;
	}
}
