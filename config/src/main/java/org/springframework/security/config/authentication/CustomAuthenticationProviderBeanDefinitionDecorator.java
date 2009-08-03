package org.springframework.security.config.authentication;

import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.Elements;
import org.w3c.dom.Node;

/**
 * Adds the decorated {@link org.springframework.security.authentication.AuthenticationProvider} to the ProviderManager's
 * list.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class CustomAuthenticationProviderBeanDefinitionDecorator implements BeanDefinitionDecorator {
    @SuppressWarnings("deprecation")
    public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder holder, ParserContext parserContext) {
        //ConfigUtils.addAuthenticationProvider(parserContext, holder.getBeanName(), (Element) node);
        parserContext.getReaderContext().warning(Elements.CUSTOM_AUTH_PROVIDER + " is deprecated in " +
                "Spring Security 3.0 and has no effect. Authentication providers should be declared within" +
                " the <authentication-provider> element", parserContext.extractSource(node));

        return holder;
    }
}
