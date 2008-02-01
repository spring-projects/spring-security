package org.springframework.security.config;

import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;

/**
 * Just registers an alias name for the default ProviderManager used by the namespace
 * configuration, allowing users to reference it in their beans and clearly see where the name is
 * coming from.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthenticationManagerBeanDefinitionParser implements BeanDefinitionParser {
    private static final String ATT_ALIAS = "alias";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        String alias = element.getAttribute(ATT_ALIAS);

        if (!StringUtils.hasText(alias)) {
            parserContext.getReaderContext().error(ATT_ALIAS + " is required.", element );
        }

        parserContext.getRegistry().registerAlias(BeanIds.AUTHENTICATION_MANAGER, alias);

        return null;
    }
}
