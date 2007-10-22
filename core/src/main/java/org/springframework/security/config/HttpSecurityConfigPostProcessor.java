package org.springframework.security.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.intercept.web.FilterChainMap;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.util.Assert;

import javax.servlet.Filter;
import java.util.*;

/**
 * Responsible for tying up the HTTP security configuration - building ordered filter stack and linking up
 * with other beans.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class HttpSecurityConfigPostProcessor implements BeanFactoryPostProcessor, Ordered {
    private Log logger = LogFactory.getLog(getClass());

    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        HttpSessionContextIntegrationFilter httpSCIF = (HttpSessionContextIntegrationFilter)
                beanFactory.getBean(HttpSecurityBeanDefinitionParser.DEFAULT_HTTP_SESSION_FILTER_ID);
        AuthenticationManager authManager =
                (AuthenticationManager) getBeanOfType(AuthenticationManager.class, beanFactory);

        configureAuthenticationEntryPoint(beanFactory);

        configureFilterChain(beanFactory);
    }

    /**
     * Selects the entry point that should be used in ExceptionTranslationFilter. Strategy is
     *
     * <ol>
     * <li>If only one use that.</li>
     * <li>If more than one, check the default interactive login Ids in order of preference</li>
     * <li>throw an exception (for now). TODO: Examine additional beans and types and make decision</li>
     * </ol>
     *
     *
     * @param beanFactory
     */
    private void configureAuthenticationEntryPoint(ConfigurableListableBeanFactory beanFactory) {
        logger.info("Selecting AuthenticationEntryPoint for use in ExceptionTranslationFilter");

        BeanDefinition etf =
                beanFactory.getBeanDefinition(HttpSecurityBeanDefinitionParser.DEFAULT_EXCEPTION_TRANSLATION_FILTER_ID);
        Map entryPointMap = beanFactory.getBeansOfType(AuthenticationEntryPoint.class);
        List entryPoints = new ArrayList(entryPointMap.values());

        Assert.isTrue(entryPoints.size() > 0, "No AuthenticationEntryPoint instances defined");

        AuthenticationEntryPoint mainEntryPoint = (AuthenticationEntryPoint)
                entryPointMap.get(FormLoginBeanDefinitionParser.DEFAULT_FORM_LOGIN_ENTRY_POINT_ID);

        if (mainEntryPoint == null) {
            throw new SecurityConfigurationException("Failed to resolve authentication entry point");
        }

        logger.info("Main AuthenticationEntryPoint set to " + mainEntryPoint);

        etf.getPropertyValues().addPropertyValue("authenticationEntryPoint", mainEntryPoint);
    }

    private void configureFilterChain(ConfigurableListableBeanFactory beanFactory) {
        FilterChainProxy filterChainProxy =
                (FilterChainProxy) beanFactory.getBean(HttpSecurityBeanDefinitionParser.DEFAULT_FILTER_CHAIN_PROXY_ID);
        // Set the default match
        List defaultFilterChain = orderFilters(beanFactory);

        // Note that this returns a copy
        Map filterMap = filterChainProxy.getFilterChainMap();

        String allUrlsMatch = filterChainProxy.getMatcher().getUniversalMatchPattern();

        filterMap.put(allUrlsMatch, defaultFilterChain);

        filterChainProxy.setFilterChainMap(filterMap);        
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

            if (!(filter instanceof Ordered)) {
                // TODO: Possibly log this as a warning and skip this filter.
                throw new IllegalArgumentException("Filter " + id + " must implement the Ordered interface");
            }

            orderedFilters.add(filter);
        }

        Collections.sort(orderedFilters, new OrderComparator());

        return orderedFilters;
    }

    private Object getBeanOfType(Class clazz, ConfigurableListableBeanFactory beanFactory) {
        Map beans = beanFactory.getBeansOfType(clazz);

        Assert.isTrue(beans.size() == 1, "Required a single bean of type " + clazz + " but found " + beans.size());

        return beans.values().toArray()[0];
    }

    public int getOrder() {
        return 0;
    }
}
