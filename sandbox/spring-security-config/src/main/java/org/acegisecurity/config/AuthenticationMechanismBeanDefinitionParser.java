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
package org.acegisecurity.config;
import org.acegisecurity.providers.ProviderManager;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * * {@link BeanDefinitionParser} for the <code>authentication-mechanism</code> tag, 
 * resolves to  {@link org.acegisecurity.providers.ProviderManager} </br>
	
 * @author vpuri
 * @see {@link org.springframework.beans.factory.BeanFactory}
 * @see {@link org.acegisecurity.providers.ProviderManager}
 * 
 */
public class AuthenticationMechanismBeanDefinitionParser extends AbstractBeanDefinitionParser implements
		BeanDefinitionParser {
	// ~ Instance fields
	// ================================================================================================

	private static final String AUTHENTICATION_JDBC = "authentication-jdbc";

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
				//this.providerExists = true;

				if (AUTHENTICATION_JDBC.equals(node.getLocalName())) {
					String attribute = childElement.getAttribute(REF);
					if (StringUtils.hasLength(attribute)) {
						// create a beandefinition
						providers.add(new RuntimeBeanReference(attribute));
					}

				}
				// TODO:Add other providers here
			}
			authMechanismBeanDef.getPropertyValues().addPropertyValue("providers", providers);

		}
		return authMechanismBeanDef;
	}
	/**
	 * Creates a default bean definition.
	 * @return
	 */
	protected static RootBeanDefinition createBeanDefinitionWithDefaults() {
		RootBeanDefinition authMechanismBeanDef = new RootBeanDefinition(ProviderManager.class);
		ManagedList providers = new ManagedList();
		// create authentication-repository (DaoAuthenticationProvider) and add that to list
		RootBeanDefinition authRepo = AuthenticationRepositoryBeanDefinitionParser.createBeanDefinitionWithDefaults();
		providers.add(authRepo);
		authMechanismBeanDef.getPropertyValues().addPropertyValue("providers", providers);
		return authMechanismBeanDef;
	}
	
}
