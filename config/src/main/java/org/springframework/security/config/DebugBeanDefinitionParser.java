package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.debug.SecurityDebugBeanFactoryPostProcessor;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 */
public class DebugBeanDefinitionParser implements BeanDefinitionParser {
    public BeanDefinition parse(Element element, ParserContext parserContext) {
        RootBeanDefinition debugPP = new RootBeanDefinition(SecurityDebugBeanFactoryPostProcessor.class);
        parserContext.getReaderContext().registerWithGeneratedName(debugPP);

        return null;
    }
}
