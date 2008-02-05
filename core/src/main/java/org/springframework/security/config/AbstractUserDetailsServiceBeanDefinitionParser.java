package org.springframework.security.config;

import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class AbstractUserDetailsServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) throws BeanDefinitionStoreException {
        String id = super.resolveId(element, definition, parserContext);

        if (StringUtils.hasText(id)) {
            return id;
        }

        // If it's nested in a parent auth-provider, generate an id automatically
        if(Elements.AUTHENTICATION_PROVIDER.equals(element.getParentNode().getNodeName())) {
            return parserContext.getReaderContext().generateBeanName(definition);
        }

        // If top level, use the default name or throw an exception if already used
        if (parserContext.getRegistry().containsBeanDefinition(BeanIds.USER_DETAILS_SERVICE)) {
            throw new BeanDefinitionStoreException("No id supplied and another " +
                    "bean is already registered as " + BeanIds.USER_DETAILS_SERVICE);
        }

        return BeanIds.USER_DETAILS_SERVICE;
    }
}
