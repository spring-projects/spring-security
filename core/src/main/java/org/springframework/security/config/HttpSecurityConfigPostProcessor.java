package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.BeansException;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.AuthenticationManager;
import org.springframework.util.Assert;

import javax.servlet.Filter;
import java.util.Map;

/**
 * Responsible for tying up the HTTP security configuration - building ordered filter stack and linking up
 * with other beans.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class HttpSecurityConfigPostProcessor implements BeanFactoryPostProcessor {
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        FilterChainProxy filterChainProxy =
                (FilterChainProxy) beanFactory.getBean(HttpSecurityBeanDefinitionParser.DEFAULT_FILTER_CHAIN_PROXY_ID);

        HttpSessionContextIntegrationFilter httpSCIF = (HttpSessionContextIntegrationFilter)
                beanFactory.getBean(HttpSecurityBeanDefinitionParser.DEFAULT_HTTP_SESSION_FILTER_ID);

        AuthenticationManager authManager =
                (AuthenticationManager) getBeanOfType(AuthenticationManager.class, beanFactory);


        //
        Map filters = beanFactory.getBeansOfType(Filter.class);








    }

    private void configureFilterChain(ConfigurableListableBeanFactory beanFactory) {


    }



    private Object getBeanOfType(Class clazz, ConfigurableListableBeanFactory beanFactory) {
        Map beans = beanFactory.getBeansOfType(clazz);

        Assert.isTrue(beans.size() == 1, "Required a single bean of type " + clazz + " but found " + beans.size());

        return beans.values().toArray()[0];
    }
}
