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

        if (parserContext.getRegistry().containsBeanDefinition(BeanIds.USER_DETAILS_SERVICE)) {
            throw new SecurityConfigurationException("No id supplied in <" + element.getNodeName() + "> and another " +
                    "bean is already registered as " + BeanIds.USER_DETAILS_SERVICE);
        }

        return BeanIds.USER_DETAILS_SERVICE;
    }
}
