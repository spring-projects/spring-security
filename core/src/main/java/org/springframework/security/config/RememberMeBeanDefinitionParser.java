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
 * @author Ben Alex
 * @version $Id$
 */
public class RememberMeBeanDefinitionParser implements BeanDefinitionParser {
    static final String ATT_KEY = "key";
	static final String ATT_DATA_SOURCE = "dataSource";
	static final String ATT_TOKEN_REPOSITORY = "tokenRepository";
	protected final Log logger = LogFactory.getLog(getClass());

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinition filter = new RootBeanDefinition(RememberMeProcessingFilter.class);
        BeanDefinition services = new RootBeanDefinition(PersistentTokenBasedRememberMeServices.class);

        filter.getPropertyValues().addPropertyValue("authenticationManager",
                new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));

        String tokenRepository = element.getAttribute(ATT_TOKEN_REPOSITORY);
        String dataSource      = element.getAttribute(ATT_DATA_SOURCE);
        String key             = element.getAttribute(ATT_KEY);

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
                ((BeanDefinition)tokenRepo).getPropertyValues().addPropertyValue(ATT_DATA_SOURCE,
                        new RuntimeBeanReference(dataSource));
            }
            services.getPropertyValues().addPropertyValue(ATT_TOKEN_REPOSITORY, tokenRepo);
        } else {
            isPersistent = false;
            services = new RootBeanDefinition(TokenBasedRememberMeServices.class);
        }
        
        if (StringUtils.hasText(key) && isPersistent) {
            logger.warn("The attribute 'key' ('" + key + "') is not required for persistent remember-me services and " +
                    "will be ignored.");
        }

        services.getPropertyValues().addPropertyValue(ATT_KEY, key);

        BeanDefinition authManager = ConfigUtils.registerProviderManagerIfNecessary(parserContext);
        BeanDefinition provider = new RootBeanDefinition(RememberMeAuthenticationProvider.class);
        provider.getPropertyValues().addPropertyValue(ATT_KEY, key);

        ManagedList providers = (ManagedList) authManager.getPropertyValues().getPropertyValue("providers").getValue();
        providers.add(provider);

        filter.getPropertyValues().addPropertyValue("rememberMeServices",
                new RuntimeBeanReference(BeanIds.REMEMBER_ME_SERVICES));

        parserContext.getRegistry().registerBeanDefinition(BeanIds.REMEMBER_ME_SERVICES, services);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.REMEMBER_ME_FILTER, filter);

        return null;
    }
}
