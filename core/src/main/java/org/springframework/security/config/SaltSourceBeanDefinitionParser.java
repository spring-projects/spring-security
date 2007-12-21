package org.springframework.security.config;

import org.springframework.security.providers.dao.salt.ReflectionSaltSource;
import org.springframework.security.providers.dao.salt.SystemWideSaltSource;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class SaltSourceBeanDefinitionParser implements BeanDefinitionParser {
    static final String ATT_USER_PROPERTY = "user-property";
    static final String ATT_SYSTEM_WIDE = "system-wide";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinition saltSource;
        String userProperty = element.getAttribute(ATT_USER_PROPERTY);

        if (StringUtils.hasText(userProperty)) {
            saltSource = new RootBeanDefinition(ReflectionSaltSource.class);
            saltSource.getPropertyValues().addPropertyValue("userPropertyToUse", userProperty);

            return saltSource;
        }

        String systemWideSalt = element.getAttribute(ATT_SYSTEM_WIDE);

        if (StringUtils.hasText(systemWideSalt)) {
            saltSource = new RootBeanDefinition(SystemWideSaltSource.class);
            saltSource.getPropertyValues().addPropertyValue("systemWideSalt", systemWideSalt);

            return saltSource;
        }

        throw new SecurityConfigurationException(Elements.SALT_SOURCE + " requires an attribute");
    }
}
