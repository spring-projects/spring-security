package org.springframework.security.config;

import java.util.Map;

import org.springframework.beans.BeanWrapperImpl;
import org.springframework.beans.BeansException;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.security.providers.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.ui.rememberme.AbstractRememberMeServices;
import org.springframework.security.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.util.Assert;

/**
 * Registered by {@link HttpSecurityBeanDefinitionParser} to inject a UserDetailsService into
 * the X509Provider, RememberMeServices and OpenIDAuthenticationProvider instances created by
 * the namespace.
 *
 * @author Luke Taylor
 * @since 2.0.2
 */
public class UserDetailsServiceInjectionBeanPostProcessor implements BeanPostProcessor, BeanFactoryAware {
    private ConfigurableListableBeanFactory beanFactory;

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (BeanIds.X509_AUTH_PROVIDER.equals(beanName)) {
            injectUserDetailsServiceIntoX509Provider((PreAuthenticatedAuthenticationProvider) bean);
        } else if (BeanIds.REMEMBER_ME_SERVICES.equals(beanName)) {
            injectUserDetailsServiceIntoRememberMeServices((AbstractRememberMeServices)bean);
        } else if (BeanIds.OPEN_ID_PROVIDER.equals(beanName)) {
            injectUserDetailsServiceIntoOpenIDProvider(bean);
        }

        return bean;
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    private void injectUserDetailsServiceIntoRememberMeServices(AbstractRememberMeServices services) {
        BeanDefinition beanDefinition = beanFactory.getBeanDefinition(BeanIds.REMEMBER_ME_SERVICES);
        PropertyValue pv = beanDefinition.getPropertyValues().getPropertyValue("userDetailsService");

        if (pv == null) {
            services.setUserDetailsService(getUserDetailsService());
        } else {
            UserDetailsService cachingUserService = getCachingUserService(pv.getValue());

            if (cachingUserService != null) {
                services.setUserDetailsService(cachingUserService);
            }
        }
    }

    private void injectUserDetailsServiceIntoX509Provider(PreAuthenticatedAuthenticationProvider provider) {
        BeanDefinition beanDefinition = beanFactory.getBeanDefinition(BeanIds.X509_AUTH_PROVIDER);
        PropertyValue pv = beanDefinition.getPropertyValues().getPropertyValue("preAuthenticatedUserDetailsService");
        UserDetailsByNameServiceWrapper wrapper = new UserDetailsByNameServiceWrapper();

        if (pv == null) {
            wrapper.setUserDetailsService(getUserDetailsService());
            provider.setPreAuthenticatedUserDetailsService(wrapper);
        } else {
            RootBeanDefinition preAuthUserService = (RootBeanDefinition) pv.getValue();
            Object userService =
                preAuthUserService.getPropertyValues().getPropertyValue("userDetailsService").getValue();

            UserDetailsService cachingUserService = getCachingUserService(userService);

            if (cachingUserService != null) {
                wrapper.setUserDetailsService(cachingUserService);
                provider.setPreAuthenticatedUserDetailsService(wrapper);
            }
        }
    }

    private void injectUserDetailsServiceIntoOpenIDProvider(Object bean) {
        BeanDefinition beanDefinition = beanFactory.getBeanDefinition(BeanIds.OPEN_ID_PROVIDER);
        PropertyValue pv = beanDefinition.getPropertyValues().getPropertyValue("userDetailsService");

        if (pv == null) {
            BeanWrapperImpl beanWrapper = new BeanWrapperImpl(bean);
            beanWrapper.setPropertyValue("userDetailsService", getUserDetailsService());
        }
    }


    /**
     * Obtains a user details service for use in RememberMeServices etc. Will return a caching version
     * if available so should not be used for beans which need to separate the two.
     */
    UserDetailsService getUserDetailsService() {
        Map<?,?> beans = beanFactory.getBeansOfType(CachingUserDetailsService.class);

        if (beans.size() == 0) {
            beans = beanFactory.getBeansOfType(UserDetailsService.class);
        }

        if (beans.size() == 0) {
            throw new SecurityConfigurationException("No UserDetailsService registered.");

        } else if (beans.size() > 1) {
            throw new SecurityConfigurationException("More than one UserDetailsService registered. Please " +
                    "use a specific Id reference in <remember-me/> <openid-login/> or <x509 /> elements.");
        }

        return (UserDetailsService) beans.values().toArray()[0];
    }

    private UserDetailsService getCachingUserService(Object userServiceRef) {
        Assert.isInstanceOf(RuntimeBeanReference.class, userServiceRef,
                "userDetailsService property value must be a RuntimeBeanReference");

        String id = ((RuntimeBeanReference)userServiceRef).getBeanName();
        // Overwrite with the caching version if available
        String cachingId = id + AbstractUserDetailsServiceBeanDefinitionParser.CACHING_SUFFIX;

        if (beanFactory.containsBeanDefinition(cachingId)) {
            return (UserDetailsService) beanFactory.getBean(cachingId);
        }

        return null;
    }


    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = (ConfigurableListableBeanFactory) beanFactory;
    }
}
