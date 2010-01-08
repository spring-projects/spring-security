package org.springframework.security.config.authentication;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.dao.ReflectionSaltSource;
import org.springframework.security.authentication.dao.SystemWideSaltSource;
import org.springframework.security.config.Elements;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @since 2.0
 */
class SaltSourceBeanDefinitionParser {
    private static final String ATT_USER_PROPERTY = "user-property";
    private static final String ATT_REF = "ref";
    private static final String ATT_SYSTEM_WIDE = "system-wide";

    public BeanMetadataElement parse(Element element, ParserContext parserContext) {
        String ref = element.getAttribute(ATT_REF);

        if (StringUtils.hasText(ref)) {
            return new RuntimeBeanReference(ref);
        }

        String userProperty = element.getAttribute(ATT_USER_PROPERTY);
        RootBeanDefinition saltSource;

        if (StringUtils.hasText(userProperty)) {
            saltSource = new RootBeanDefinition(ReflectionSaltSource.class);
            saltSource.getPropertyValues().addPropertyValue("userPropertyToUse", userProperty);
            saltSource.setSource(parserContext.extractSource(element));
            saltSource.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

            return saltSource;
        }

        String systemWideSalt = element.getAttribute(ATT_SYSTEM_WIDE);

        if (StringUtils.hasText(systemWideSalt)) {
            saltSource = new RootBeanDefinition(SystemWideSaltSource.class);
            saltSource.getPropertyValues().addPropertyValue("systemWideSalt", systemWideSalt);
            saltSource.setSource(parserContext.extractSource(element));
            saltSource.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

            return saltSource;
        }

        parserContext.getReaderContext().error(Elements.SALT_SOURCE + " requires an attribute", element);
        return null;
    }
}
