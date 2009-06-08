package org.springframework.security.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.web.authentication.AnonymousProcessingFilter;
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
    static final String DEF_USERNAME = "anonymousUser";

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

        RootBeanDefinition provider = new RootBeanDefinition(AnonymousAuthenticationProvider.class);
        provider.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        provider.setSource(source);
        provider.getPropertyValues().addPropertyValue(ATT_KEY, key);

        parserContext.getRegistry().registerBeanDefinition(BeanIds.ANONYMOUS_AUTHENTICATION_PROVIDER, provider);
        ConfigUtils.addAuthenticationProvider(parserContext, BeanIds.ANONYMOUS_AUTHENTICATION_PROVIDER);

        parserContext.getRegistry().registerBeanDefinition(BeanIds.ANONYMOUS_PROCESSING_FILTER, filter);
        ConfigUtils.addHttpFilter(parserContext, new RuntimeBeanReference(BeanIds.ANONYMOUS_PROCESSING_FILTER));
        parserContext.registerComponent(new BeanComponentDefinition(filter, BeanIds.ANONYMOUS_PROCESSING_FILTER));

        return null;
    }
}
