package org.springframework.security.config;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.util.Assert;

/**
 * Extended version of {@link ProviderManager the default authentication manager} which lazily initializes
 * the list of {@link AuthenticationProvider}s. This prevents some of the issues that have occurred with
 * namespace configuration where early instantiation of a security interceptor has caused the AuthenticationManager
 * and thus dependent beans (typically UserDetailsService implementations or DAOs) to be initialized too early.
 *
 * @author Luke Taylor
 * @since 2.0.4
 */
public class NamespaceAuthenticationManager extends ProviderManager implements BeanFactoryAware {
    BeanFactory beanFactory;
    List<String> providerBeanNames;

    public void setBeanFactory(BeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(providerBeanNames, "provideBeanNames has not been set");
        Assert.notEmpty(providerBeanNames, "No authentication providers were found in the application context");

        super.afterPropertiesSet();
    }

    /**
     * Overridden to lazily-initialize the list of providers on first use.
     */
    public List<AuthenticationProvider> getProviders() {
        // We use the names array to determine whether the list has been set yet.
        if (providerBeanNames != null) {
            ArrayList<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>();
            Iterator<String> beanNames = providerBeanNames.iterator();

            while (beanNames.hasNext()) {
                providers.add((AuthenticationProvider) beanFactory.getBean(beanNames.next()));
            }
            providerBeanNames = null;
            providers.trimToSize();

            setProviders(providers);
        }

        return super.getProviders();
    }

    public void setProviderBeanNames(List<String> provideBeanNames) {
        this.providerBeanNames = provideBeanNames;
    }
}
