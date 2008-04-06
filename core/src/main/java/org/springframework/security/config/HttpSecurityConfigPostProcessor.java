package org.springframework.security.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.core.Ordered;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.security.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.util.Assert;

/**
 * Responsible for tying up the HTTP security configuration once all the beans are registered.
 * This class does not actually instantiate any beans (for example, it should not call {@link BeanFactory#getBean(String)}).
 * All the wiring up should be done using bean definitions or bean references to avoid this. This approach should avoid any
 * conflict with other processors.
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 * @since 2.0
 */
public class HttpSecurityConfigPostProcessor implements BeanFactoryPostProcessor, Ordered {
    private Log logger = LogFactory.getLog(getClass());

    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        injectUserDetailsServiceIntoRememberMeServices(beanFactory);
        injectUserDetailsServiceIntoX509Provider(beanFactory);
        injectUserDetailsServiceIntoOpenIDProvider(beanFactory);
        injectAuthenticationEntryPointIntoExceptionTranslationFilter(beanFactory);
    }

    private void injectUserDetailsServiceIntoRememberMeServices(ConfigurableListableBeanFactory bf) {
        try {
            BeanDefinition rememberMeServices = bf.getBeanDefinition(BeanIds.REMEMBER_ME_SERVICES);
            PropertyValue pv = rememberMeServices.getPropertyValues().getPropertyValue("userDetailsService");

            if (pv == null) {
                rememberMeServices.getPropertyValues().addPropertyValue("userDetailsService",
                    ConfigUtils.getUserDetailsService(bf));
            } else {
            	RuntimeBeanReference cachingUserService = getCachingUserService(bf, pv.getValue());
            	
            	if (cachingUserService != null) {
            		rememberMeServices.getPropertyValues().addPropertyValue("userDetailsService", cachingUserService);
            	}            	
            }
        } catch (NoSuchBeanDefinitionException e) {
            // ignore
        }
    }

    private void injectUserDetailsServiceIntoX509Provider(ConfigurableListableBeanFactory bf) {
        try {
            BeanDefinition x509AuthProvider = bf.getBeanDefinition(BeanIds.X509_AUTH_PROVIDER);
            PropertyValue pv = x509AuthProvider.getPropertyValues().getPropertyValue("preAuthenticatedUserDetailsService");

            if (pv == null) {
            	BeanDefinitionBuilder preAuthUserService = BeanDefinitionBuilder.rootBeanDefinition(UserDetailsByNameServiceWrapper.class);
            	preAuthUserService.addPropertyValue("userDetailsService", ConfigUtils.getUserDetailsService(bf));
                x509AuthProvider.getPropertyValues().addPropertyValue("preAuthenticatedUserDetailsService",
                        preAuthUserService.getBeanDefinition());
            } else {
            	RootBeanDefinition preAuthUserService = (RootBeanDefinition) pv.getValue();
            	Object userService = 
            		preAuthUserService.getPropertyValues().getPropertyValue("userDetailsService").getValue();
            	
            	RuntimeBeanReference cachingUserService = getCachingUserService(bf, userService);
            	
            	if (cachingUserService != null) {
            		preAuthUserService.getPropertyValues().addPropertyValue("userDetailsService", cachingUserService);
            	}
            }
        } catch (NoSuchBeanDefinitionException e) {
            // ignore
        }
    }
    
    private void injectUserDetailsServiceIntoOpenIDProvider(ConfigurableListableBeanFactory beanFactory) {
        try {
            BeanDefinition openIDProvider = beanFactory.getBeanDefinition(BeanIds.OPEN_ID_PROVIDER);
            PropertyValue pv = openIDProvider.getPropertyValues().getPropertyValue("userDetailsService");

            if (pv == null) {
                openIDProvider.getPropertyValues().addPropertyValue("userDetailsService",
                    ConfigUtils.getUserDetailsService(beanFactory));
            }
        } catch (NoSuchBeanDefinitionException e) {
            // ignore
        }
    }
    
    private RuntimeBeanReference getCachingUserService(ConfigurableListableBeanFactory bf, Object userServiceRef) {
    	Assert.isInstanceOf(RuntimeBeanReference.class, userServiceRef, 
    			"userDetailsService property value must be a RuntimeBeanReference");
    	
    	String id = ((RuntimeBeanReference)userServiceRef).getBeanName();
    	// Overwrite with the caching version if available
    	String cachingId = id + AbstractUserDetailsServiceBeanDefinitionParser.CACHING_SUFFIX;
    	
    	if (bf.containsBeanDefinition(cachingId)) {
    		return new RuntimeBeanReference(cachingId);
    	}
    	
    	return null;
    }

    /**
     * Selects the entry point that should be used in ExceptionTranslationFilter. If an entry point has been
     * set during parsing of form, openID and basic authentication information, or via a custom reference
     * (using <tt>custom-entry-point</tt>, then that will be used. Otherwise there
     * must be a single entry point bean and that will be used.
     * 
     * Todo: this could probably be more easily be done in a BeanPostProcessor for ExceptionTranslationFilter.
     *
     */
    private void injectAuthenticationEntryPointIntoExceptionTranslationFilter(ConfigurableListableBeanFactory beanFactory) {
        logger.info("Selecting AuthenticationEntryPoint for use in ExceptionTranslationFilter");        
        
        BeanDefinition etf =
                beanFactory.getBeanDefinition(BeanIds.EXCEPTION_TRANSLATION_FILTER);
        
        String entryPoint = null;
        
        if (beanFactory.containsBean(BeanIds.MAIN_ENTRY_POINT)) {
            entryPoint = BeanIds.MAIN_ENTRY_POINT;
            logger.info("Using main configured AuthenticationEntryPoint set to " + BeanIds.MAIN_ENTRY_POINT);
        } else {
            String[] entryPoints = beanFactory.getBeanNamesForType(AuthenticationEntryPoint.class);
            Assert.isTrue(entryPoints.length != 0, "No AuthenticationEntryPoint instances defined");
            Assert.isTrue(entryPoints.length == 1, "More than one AuthenticationEntryPoint defined in context");
            entryPoint = entryPoints[0];
        }
        
        logger.info("Using bean '" + entryPoint + "' as the entry point.");
        etf.getPropertyValues().addPropertyValue("authenticationEntryPoint", new RuntimeBeanReference(entryPoint));
    }

    public int getOrder() {
        return HIGHEST_PRECEDENCE + 1;
    }
}
