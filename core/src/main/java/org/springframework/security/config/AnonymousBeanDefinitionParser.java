package org.springframework.security.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.providers.anonymous.AnonymousAuthenticationProvider;
import org.springframework.security.providers.anonymous.AnonymousProcessingFilter;
import org.w3c.dom.Element;

/**
 * @author Ben Alex
 * @version $Id: RememberMeBeanDefinitionParser.java 2231 2007-11-07 13:29:15Z luke_t $
 */
public class AnonymousBeanDefinitionParser implements BeanDefinitionParser {
    protected final Log logger = LogFactory.getLog(getClass());

    public static final String DEFAULT_ANONYMOUS_FILTER_ID = "_anonymousProcessingFilter";
    public static final String DEFAULT_ANONYMOUS_AUTHENTICATION_PROVIDER_ID = "_anonymousAuthenticationProvider";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinition filter = new RootBeanDefinition(AnonymousProcessingFilter.class);

        String grantedAuthority = element.getAttribute("grantedAuthority");
        String username         = element.getAttribute("username");
        String key              = element.getAttribute("key");

        filter.getPropertyValues().addPropertyValue("userAttribute", username + "," + grantedAuthority);
        filter.getPropertyValues().addPropertyValue("key", key);

        BeanDefinition authManager = ConfigUtils.registerProviderManagerIfNecessary(parserContext);
        BeanDefinition provider = new RootBeanDefinition(AnonymousAuthenticationProvider.class);
        provider.getPropertyValues().addPropertyValue("key", key);

        ManagedList authMgrProviderList = (ManagedList) authManager.getPropertyValues().getPropertyValue("providers").getValue();
        authMgrProviderList.add(provider);

        parserContext.getRegistry().registerBeanDefinition(DEFAULT_ANONYMOUS_FILTER_ID, filter);

        return null;
    }
}
