package org.springframework.security.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ui.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.ui.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.ui.rememberme.RememberMeProcessingFilter;
import org.springframework.security.ui.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.providers.rememberme.RememberMeAuthenticationProvider;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class RememberMeBeanDefinitionParser implements BeanDefinitionParser {
    protected final Log logger = LogFactory.getLog(getClass());

    public static final String DEFAULT_REMEMBER_ME_FILTER_ID = "_rememberMeFilter";
    public static final String DEFAULT_REMEMBER_ME_SERVICES_ID = "_rememberMeServices";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinition filter = new RootBeanDefinition(RememberMeProcessingFilter.class);
        BeanDefinition services = new RootBeanDefinition(PersistentTokenBasedRememberMeServices.class);

        filter.getPropertyValues().addPropertyValue("authenticationManager",
                new RuntimeBeanReference(ConfigUtils.DEFAULT_AUTH_MANAGER_ID));

        String tokenRepository = element.getAttribute("tokenRepository");
        String dataSource      = element.getAttribute("dataSource");
        String key             = element.getAttribute("key");

        boolean dataSourceSet = StringUtils.hasText(dataSource);
        boolean tokenRepoSet = StringUtils.hasText(tokenRepository);

        if (dataSourceSet && tokenRepoSet) {
            throw new SecurityConfigurationException("Specify tokenRepository or dataSource but not both");
        }

        boolean isPersistent = dataSourceSet | tokenRepoSet;

        if (isPersistent) {
            Object tokenRepo;

            if (tokenRepoSet) {
                tokenRepo = new RuntimeBeanReference(tokenRepository);
            } else {
                tokenRepo = new RootBeanDefinition(JdbcTokenRepositoryImpl.class);
                ((BeanDefinition)tokenRepo).getPropertyValues().addPropertyValue("dataSource",
                        new RuntimeBeanReference(dataSource));
            }
            services.getPropertyValues().addPropertyValue("tokenRepository", tokenRepo);
        } else {
            isPersistent = false;
            services = new RootBeanDefinition(TokenBasedRememberMeServices.class);
        }
        
        if (StringUtils.hasText(key) && isPersistent) {
            logger.warn("The attribute 'key' ('" + key + "') is not required for persistent remember-me services and " +
                    "will be ignored.");
        }

        services.getPropertyValues().addPropertyValue("key", key);

        BeanDefinition authManager = ConfigUtils.registerProviderManagerIfNecessary(parserContext);
        BeanDefinition provider = new RootBeanDefinition(RememberMeAuthenticationProvider.class);
        provider.getPropertyValues().addPropertyValue("key", key);

        ManagedList providers = (ManagedList) authManager.getPropertyValues().getPropertyValue("providers").getValue();
        providers.add(provider);

        filter.getPropertyValues().addPropertyValue("rememberMeServices",
                new RuntimeBeanReference(DEFAULT_REMEMBER_ME_SERVICES_ID));

        parserContext.getRegistry().registerBeanDefinition(DEFAULT_REMEMBER_ME_SERVICES_ID, services);
        parserContext.getRegistry().registerBeanDefinition(DEFAULT_REMEMBER_ME_FILTER_ID, filter);

        return null;
    }
}
