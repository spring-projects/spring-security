/**
 * 
 */
package org.acegisecurity.config;

import java.util.ArrayList;
import java.util.List;

import org.acegisecurity.providers.ProviderManager;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
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
 * @author vpuri
 * 
 */
public class AuthenticationMechanismBeanDefinitionParser extends AbstractBeanDefinitionParser implements
		BeanDefinitionParser {

	private static final Object AUTHENTICATION_JDBC = "authentication-jdbc";

	private static final String REF = "ref";

	private boolean providerExists = false;


	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
		
		ManagedList providers = new ManagedList();
		Assert.notNull(parserContext, "ParserContext must not be null");
		RootBeanDefinition authMechanismBeanDef = new RootBeanDefinition(ProviderManager.class);
		NodeList childNodes = element.getChildNodes();

		for (int i = 0, n = childNodes.getLength(); i < n; i++) {
			Node node = childNodes.item(i);

			if (node.getNodeType() == Node.ELEMENT_NODE) {
				Element childElement = (Element) node;
				providerExists = true;

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

		if (!providerExists) {
			RootBeanDefinition rootBeanDefinition = new RootBeanDefinition(AuthenticationProviderOrderResolver.class);
			BeanDefinitionHolder beanDefinitionHolder = new BeanDefinitionHolder(rootBeanDefinition,
					"providerOrderResolver");
			registerBeanDefinition(beanDefinitionHolder, parserContext.getRegistry());
		}

		return authMechanismBeanDef;

	}
}
