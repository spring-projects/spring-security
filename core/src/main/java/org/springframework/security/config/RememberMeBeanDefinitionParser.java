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
    static final String DEF_KEY = "SpringSecured";

	static final String ATT_DATA_SOURCE = "data-source-ref";
	static final String ATT_SERVICES_REF = "services-ref";
	static final String ATT_TOKEN_REPOSITORY = "token-repository-ref";
	static final String ATT_USER_SERVICE_REF = "user-service-ref";
	static final String ATT_TOKEN_VALIDITY = "token-validity-seconds";

	protected final Log logger = LogFactory.getLog(getClass());
	private String servicesName;

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        String tokenRepository = null;
        String dataSource = null;
        String key = null;
        Object source = null;
        String userServiceRef = null;
        String rememberMeServicesRef = null;
        String tokenValiditySeconds = null;

        if (element != null) {
            tokenRepository = element.getAttribute(ATT_TOKEN_REPOSITORY);
            dataSource = element.getAttribute(ATT_DATA_SOURCE);
            key = element.getAttribute(ATT_KEY);
            userServiceRef = element.getAttribute(ATT_USER_SERVICE_REF);
            rememberMeServicesRef = element.getAttribute(ATT_SERVICES_REF);
            tokenValiditySeconds = element.getAttribute(ATT_TOKEN_VALIDITY);
            source = parserContext.extractSource(element);
        }
        
        if (!StringUtils.hasText(key)) {
        	key = DEF_KEY;
        }        
        
        RootBeanDefinition services = null;

        boolean dataSourceSet = StringUtils.hasText(dataSource);
        boolean tokenRepoSet = StringUtils.hasText(tokenRepository);
        boolean servicesRefSet = StringUtils.hasText(rememberMeServicesRef);
        boolean userServiceSet = StringUtils.hasText(userServiceRef);
        boolean tokenValiditySet = StringUtils.hasText(tokenValiditySeconds);
        
        if (servicesRefSet && (dataSourceSet || tokenRepoSet || userServiceSet || tokenValiditySet)) {
    		parserContext.getReaderContext().error(ATT_SERVICES_REF + " can't be used in combination with attributes " 
    				+ ATT_TOKEN_REPOSITORY + "," + ATT_DATA_SOURCE + ", " + ATT_USER_SERVICE_REF + " or " + ATT_TOKEN_VALIDITY, source);        	
        }
        
        if (dataSourceSet && tokenRepoSet) {
            parserContext.getReaderContext().error("Specify " + ATT_TOKEN_REPOSITORY + " or " + 
            		ATT_DATA_SOURCE +" but not both", source);
        }

        boolean isPersistent = dataSourceSet | tokenRepoSet;

        if (isPersistent) {
            Object tokenRepo;
            services = new RootBeanDefinition(PersistentTokenBasedRememberMeServices.class);

            if (tokenRepoSet) {
                tokenRepo = new RuntimeBeanReference(tokenRepository);
            } else {
                tokenRepo = new RootBeanDefinition(JdbcTokenRepositoryImpl.class);
                ((BeanDefinition)tokenRepo).getPropertyValues().addPropertyValue("dataSource",
                        new RuntimeBeanReference(dataSource));
            }
            services.getPropertyValues().addPropertyValue("tokenRepository", tokenRepo);
        } else if (!servicesRefSet) {
            services = new RootBeanDefinition(TokenBasedRememberMeServices.class);
        }

        if (services != null) {
	        if (userServiceSet) {
	            services.getPropertyValues().addPropertyValue("userDetailsService", new RuntimeBeanReference(userServiceRef));
	        }
	        
	        if (tokenValiditySet) {
	        	services.getPropertyValues().addPropertyValue("tokenValiditySeconds", new Integer(tokenValiditySeconds));
	        }
	        services.setSource(source);
	        services.getPropertyValues().addPropertyValue(ATT_KEY, key);
	        parserContext.getRegistry().registerBeanDefinition(BeanIds.REMEMBER_ME_SERVICES, services);
	        servicesName = BeanIds.REMEMBER_ME_SERVICES;
        } else {
        	servicesName = rememberMeServicesRef;
        	parserContext.getRegistry().registerAlias(rememberMeServicesRef, BeanIds.REMEMBER_ME_SERVICES);
        }
        
        registerProvider(parserContext, source, key);        
        
        registerFilter(parserContext, source);

        return null;
    }
    
    String getServicesName() {
		return servicesName;
	}

	private void registerProvider(ParserContext pc, Object source, String key) {
        //BeanDefinition authManager = ConfigUtils.registerProviderManagerIfNecessary(pc);
        RootBeanDefinition provider = new RootBeanDefinition(RememberMeAuthenticationProvider.class);
        provider.setSource(source);
        provider.getPropertyValues().addPropertyValue(ATT_KEY, key);
        pc.getRegistry().registerBeanDefinition(BeanIds.REMEMBER_ME_AUTHENTICATION_PROVIDER, provider);
        ConfigUtils.addAuthenticationProvider(pc, BeanIds.REMEMBER_ME_AUTHENTICATION_PROVIDER);
    }
    
    private void registerFilter(ParserContext pc, Object source) {
        RootBeanDefinition filter = new RootBeanDefinition(RememberMeProcessingFilter.class);
        filter.setSource(source);
        filter.getPropertyValues().addPropertyValue("authenticationManager",
                new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));        
        
        filter.getPropertyValues().addPropertyValue("rememberMeServices",
                new RuntimeBeanReference(BeanIds.REMEMBER_ME_SERVICES));

        pc.getRegistry().registerBeanDefinition(BeanIds.REMEMBER_ME_FILTER, filter);
        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.REMEMBER_ME_FILTER));    	
    }
}
