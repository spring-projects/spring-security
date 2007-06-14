/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.context.HttpSessionContextIntegrationFilter;
import org.acegisecurity.ui.logout.LogoutFilter;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

/**
 * Parses 'autoconfig' tag and creates all the required
 * <code>BeanDefinition</code>s with their default configurations. It also
 * resolves their dependencies and wire them together.
 * 
 * @author Vishal Puri
 * 
 */
public class AutoConfigBeanDefinitionParser  implements BeanDefinitionParser {

	public BeanDefinition parse(Element element, ParserContext parserContext) {
		createAndRegisterBeanDefinitionForHttpSessionContextIntegrationFilter(parserContext);
		createAndRegisterBeanDefinitionForLogoutFilter(parserContext);
		
		return null;
	}

	private void createAndRegisterBeanDefinitionForLogoutFilter(ParserContext parserContext) {
		RootBeanDefinition defintion =LogoutFilterBeanDefinitionParser.doCreateBeanDefinitionWithDefaults();
		registerBeanDefinition(parserContext, defintion);
	}

	private void createAndRegisterBeanDefinitionForHttpSessionContextIntegrationFilter(ParserContext parserContext) {
		RootBeanDefinition defintion = ContextIntegrationBeanDefinitionParser.doCreateBeanDefinitionWithDefaults();
		registerBeanDefinition(parserContext, defintion);
	}

	/**
	 * @param parserContext
	 * @param defintion
	 */
	private void registerBeanDefinition(ParserContext parserContext, RootBeanDefinition defintion) {
		parserContext.getRegistry().registerBeanDefinition(parserContext.getReaderContext().generateBeanName(defintion), defintion);
	}

}
