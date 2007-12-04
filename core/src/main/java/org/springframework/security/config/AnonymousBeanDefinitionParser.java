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
    static final String ATT_KEY = "key";
	static final String ATT_USERNAME = "username";
	static final String ATT_GRANTED_AUTHORITY = "grantedAuthority";
	protected final Log logger = LogFactory.getLog(getClass());

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinition filter = new RootBeanDefinition(AnonymousProcessingFilter.class);

        String grantedAuthority = element.getAttribute(ATT_GRANTED_AUTHORITY);
        String username         = element.getAttribute(ATT_USERNAME);
        String key              = element.getAttribute(ATT_KEY);

        filter.getPropertyValues().addPropertyValue("userAttribute", username + "," + grantedAuthority);
        filter.getPropertyValues().addPropertyValue(ATT_KEY, key);

        BeanDefinition authManager = ConfigUtils.registerProviderManagerIfNecessary(parserContext);
        BeanDefinition provider = new RootBeanDefinition(AnonymousAuthenticationProvider.class);
        provider.getPropertyValues().addPropertyValue(ATT_KEY, key);

        ManagedList authMgrProviderList = (ManagedList) authManager.getPropertyValues().getPropertyValue("providers").getValue();
        authMgrProviderList.add(provider);

        parserContext.getRegistry().registerBeanDefinition(BeanIds.ANONYMOUS_PROCESSING_FILTER, filter);

        return null;
    }
}
