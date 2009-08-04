package org.springframework.security.config.method;

import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Node;

/**
 * Adds the decorated {@link org.springframework.security.access.AfterInvocationProvider} to the
 * AfterInvocationProviderManager's list.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class CustomAfterInvocationProviderBeanDefinitionDecorator implements BeanDefinitionDecorator {

    public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder holder, ParserContext parserContext) {
        parserContext.getReaderContext().warning("In Spring Security 3.0, this element is not supported and" +
                " has no effect", parserContext.extractSource(node));
//        MethodConfigUtils.getRegisteredAfterInvocationProviders(parserContext).add(holder.getBeanDefinition());

        return holder;
    }

}
