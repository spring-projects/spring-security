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
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.util.Assert;

/**
 * 
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class FilterChainProxyPostProcessor implements BeanPostProcessor, BeanFactoryAware {
    private Log logger = LogFactory.getLog(getClass());
    
    private ListableBeanFactory beanFactory;    

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if(!beanName.equals(BeanIds.FILTER_CHAIN_PROXY)) {
            return bean;
        }
        
        FilterChainProxy filterChainProxy = (FilterChainProxy) bean;
        // Set the default match
        List defaultFilterChain = orderFilters(beanFactory);

        // Note that this returns a copy
        Map filterMap = filterChainProxy.getFilterChainMap();
        String allUrlsMatch = filterChainProxy.getMatcher().getUniversalMatchPattern();

        filterMap.put(allUrlsMatch, defaultFilterChain);
        filterChainProxy.setFilterChainMap(filterMap);

        logger.info("Configured filter chain(s): " + filterChainProxy);        

        return bean;
    }

    private List orderFilters(ListableBeanFactory beanFactory) {
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

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = (ListableBeanFactory) beanFactory;
    }

}
