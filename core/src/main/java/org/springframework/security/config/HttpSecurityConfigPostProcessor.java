package org.springframework.security.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.security.concurrent.ConcurrentSessionFilter;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.security.ui.basicauth.BasicProcessingFilter;
import org.springframework.security.ui.rememberme.RememberMeServices;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.security.providers.preauth.UserDetailsByNameServiceWrapper;
import org.springframework.util.Assert;

/**
 * Responsible for tying up the HTTP security configuration - building ordered filter stack and linking up
 * with other beans.
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

        injectRememberMeServicesIntoFiltersRequiringIt(beanFactory);

        configureFilterChain(beanFactory);
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
                UserDetailsByNameServiceWrapper preAuthUserService = new UserDetailsByNameServiceWrapper();
                preAuthUserService.setUserDetailsService(ConfigUtils.getUserDetailsService(bf));
                x509AuthProvider.getPropertyValues().addPropertyValue("preAuthenticatedUserDetailsService",
                        preAuthUserService);
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
     * Sets the remember-me services, if required, on any instances of AbstractProcessingFilter and 
     * BasicProcessingFilter.
     */
    private void injectRememberMeServicesIntoFiltersRequiringIt(ConfigurableListableBeanFactory beanFactory) {
        Map beans = beanFactory.getBeansOfType(RememberMeServices.class);

        RememberMeServices rememberMeServices = null;

        if(beans.size() == 0) {
            logger.debug("No RememberMeServices configured");
            return;
        }

        if (beans.size() == 1) {
            rememberMeServices = (RememberMeServices) beans.values().toArray()[0];
        } else {
            throw new SecurityConfigurationException("More than one RememberMeServices bean found.");
        }
        
        if (rememberMeServices == null) {
            return;
        }

        // Address AbstractProcessingFilter instances
        Iterator filters = beanFactory.getBeansOfType(AbstractProcessingFilter.class).values().iterator();

        while (filters.hasNext()) {
            AbstractProcessingFilter filter = (AbstractProcessingFilter) filters.next();

            logger.info("Using RememberMeServices " + rememberMeServices + " with filter " + filter);
            filter.setRememberMeServices(rememberMeServices);
        }

        // Address BasicProcessingFilter instance, if it exists
        // NB: For remember-me to be sent back, a user must submit a "_spring_security_remember_me" with their login request.
        // Most of the time a user won't present such a parameter with their BASIC authentication request.
        // In the future we might support setting the AbstractRememberMeServices.alwaysRemember = true, but I am reluctant to
        // do so because it seems likely to lead to lower security for 99.99% of users if they set the property to true.
        if (beanFactory.containsBean(BeanIds.BASIC_AUTHENTICATION_FILTER)) {
            BasicProcessingFilter filter = (BasicProcessingFilter) beanFactory.getBean(BeanIds.BASIC_AUTHENTICATION_FILTER);

            logger.info("Using RememberMeServices " + rememberMeServices + " with filter " + filter);
            filter.setRememberMeServices(rememberMeServices);
        }
    }

    /**
     * Selects the entry point that should be used in ExceptionTranslationFilter. Strategy is
     *
     * <ol>
     * <li>If only one, use that one.</li>
     * <li>If more than one, use the form login entry point (if form login is being used), then try basic</li>
     * <li>If still null, throw an exception (for now).</li>
     * </ol>
     *
     */
    private void injectAuthenticationEntryPointIntoExceptionTranslationFilter(ConfigurableListableBeanFactory beanFactory) {
        logger.info("Selecting AuthenticationEntryPoint for use in ExceptionTranslationFilter");

        BeanDefinition etf =
                beanFactory.getBeanDefinition(BeanIds.EXCEPTION_TRANSLATION_FILTER);
        Map entryPointMap = beanFactory.getBeansOfType(AuthenticationEntryPoint.class);
        List entryPoints = new ArrayList(entryPointMap.values());

        Assert.isTrue(entryPoints.size() > 0, "No AuthenticationEntryPoint instances defined");

        AuthenticationEntryPoint mainEntryPoint;

        if (entryPoints.size() == 1) {
            mainEntryPoint = (AuthenticationEntryPoint) entryPoints.get(0);
        } else {
            mainEntryPoint = (AuthenticationEntryPoint) beanFactory.getBean(BeanIds.MAIN_ENTRY_POINT);
            
            if (mainEntryPoint == null) {
            	mainEntryPoint = (AuthenticationEntryPoint) entryPointMap.get(BeanIds.FORM_LOGIN_ENTRY_POINT);
            }

            if (mainEntryPoint == null) {
                mainEntryPoint = (AuthenticationEntryPoint) entryPointMap.get(BeanIds.BASIC_AUTHENTICATION_ENTRY_POINT);
                if (mainEntryPoint == null) {
                    throw new SecurityConfigurationException("Failed to resolve authentication entry point");
                }
            }
        }

        logger.info("Main AuthenticationEntryPoint set to " + mainEntryPoint);

        etf.getPropertyValues().addPropertyValue("authenticationEntryPoint", mainEntryPoint);
    }

    private void configureFilterChain(ConfigurableListableBeanFactory beanFactory) {
        FilterChainProxy filterChainProxy =
                (FilterChainProxy) beanFactory.getBean(BeanIds.FILTER_CHAIN_PROXY);
        // Set the default match
        List defaultFilterChain = orderFilters(beanFactory);

        // Note that this returns a copy
        Map filterMap = filterChainProxy.getFilterChainMap();

        String allUrlsMatch = filterChainProxy.getMatcher().getUniversalMatchPattern();

        filterMap.put(allUrlsMatch, defaultFilterChain);

        filterChainProxy.setFilterChainMap(filterMap);

        Map sessionFilters = beanFactory.getBeansOfType(ConcurrentSessionFilter.class);

        if (!sessionFilters.isEmpty()) {
            logger.info("Concurrent session filter in use, setting 'forceEagerSessionCreation' to true");
            HttpSessionContextIntegrationFilter scif = (HttpSessionContextIntegrationFilter)
                    beanFactory.getBean(BeanIds.HTTP_SESSION_CONTEXT_INTEGRATION_FILTER);
            scif.setForceEagerSessionCreation(true);
        }

        logger.info("Configured filter chain(s): " + filterChainProxy);
    }

    private List orderFilters(ConfigurableListableBeanFactory beanFactory) {
        Map filters = beanFactory.getBeansOfType(Filter.class);

        Assert.notEmpty(filters, "No filters found in app context!");

        Iterator ids = filters.keySet().iterator();

        List orderedFilters = new ArrayList();

        while (ids.hasNext()) {
            String id = (String) ids.next();
            Filter filter = (Filter) filters.get(id);

            if (filter instanceof FilterChainProxy) {
                continue;
            }

            // Filters must be Spring security filters or wrapped using <custom-filter>
            if (!filter.getClass().getName().startsWith("org.springframework.security")) {
                continue;
            }

            if (!(filter instanceof Ordered)) {
                logger.info("Filter " + id + " doesn't implement the Ordered interface, skipping it.");
                continue;
            }

            orderedFilters.add(filter);
        }

        Collections.sort(orderedFilters, new OrderComparator());

        return orderedFilters;
    }

    public int getOrder() {
        return HIGHEST_PRECEDENCE + 1;
    }
}
