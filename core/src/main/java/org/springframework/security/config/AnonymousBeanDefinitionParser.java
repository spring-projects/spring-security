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
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Ben Alex
 * @version $Id: RememberMeBeanDefinitionParser.java 2231 2007-11-07 13:29:15Z luke_t $
 */
public class AnonymousBeanDefinitionParser implements BeanDefinitionParser {
    static final String ATT_KEY = "key";
    static final String DEF_KEY = "doesNotMatter";

	static final String ATT_USERNAME = "username";
	static final String DEF_USERNAME = "roleAnonymous";

	static final String ATT_GRANTED_AUTHORITY = "granted-authority";
	static final String DEF_GRANTED_AUTHORITY = "ROLE_ANONYMOUS";

	protected final Log logger = LogFactory.getLog(getClass());

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        String grantedAuthority = null;
        String username = null;
        String key = null;
        Object source = null;

        if (element != null) {
            grantedAuthority = element.getAttribute(ATT_GRANTED_AUTHORITY);
            username = element.getAttribute(ATT_USERNAME);
            key = element.getAttribute(ATT_KEY);
            source = parserContext.extractSource(element);
        }

        if (!StringUtils.hasText(grantedAuthority)) {
        	grantedAuthority = DEF_GRANTED_AUTHORITY;
        }

        if (!StringUtils.hasText(username)) {
        	username = DEF_USERNAME;
        }

        if (!StringUtils.hasText(key)) {
        	key = DEF_KEY;
        }

        RootBeanDefinition filter = new RootBeanDefinition(AnonymousProcessingFilter.class);

        filter.setSource(source);
        filter.getPropertyValues().addPropertyValue("userAttribute", username + "," + grantedAuthority);
        filter.getPropertyValues().addPropertyValue(ATT_KEY, key);

        BeanDefinition authManager = ConfigUtils.registerProviderManagerIfNecessary(parserContext);
        RootBeanDefinition provider = new RootBeanDefinition(AnonymousAuthenticationProvider.class);
        provider.setSource(source);
        provider.getPropertyValues().addPropertyValue(ATT_KEY, key);

        ManagedList authMgrProviderList = (ManagedList) authManager.getPropertyValues().getPropertyValue("providers").getValue();
        authMgrProviderList.add(provider);

        parserContext.getRegistry().registerBeanDefinition(BeanIds.ANONYMOUS_PROCESSING_FILTER, filter);

        return null;
    }
}
