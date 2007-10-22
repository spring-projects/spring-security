package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.NamespaceHandlerSupport;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;


/**
 * Registers the bean definition parsers for the "security" namespace (http://www.springframework.org/schema/security).
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class SecurityNamespaceHandler extends NamespaceHandlerSupport {
    public static final String DEFAULT_FILTER_CHAIN_PROXY_ID = "_filterChainProxy";

    public void init() {
        registerBeanDefinitionParser("ldap", new LdapBeanDefinitionParser());
        registerBeanDefinitionParser("http", new HttpSecurityBeanDefinitionParser());
        registerBeanDefinitionParser("authentication-provider", new AuthenticationProviderBeanDefinitionParser());
        registerBeanDefinitionParser("autoconfig", new AutoConfigBeanDefinitionParser());
        registerBeanDefinitionDecorator("intercept-methods", new InterceptMethodsBeanDefinitionDecorator());
        registerBeanDefinitionDecorator("filter-chain-map", new FilterChainMapBeanDefinitionDecorator());        
    }

//    private class HttpSecurityBeanDefinitionParser implements BeanDefinitionParser {
//
//        public BeanDefinition parse(Element element, ParserContext parserContext) {
//            RootBeanDefinition filterChainProxy = new RootBeanDefinition(FilterChainProxy.class);
//
//            Element formLoginElt = DomUtils.getChildElementByTagName(element, "form-login");
//
//            if (formLoginElt != null) {
//                parse(formLoginElt, parserContext);
//            }
//
//            return filterChainProxy;
//        }
//    }
}
