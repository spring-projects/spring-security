package org.springframework.security.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.OrderComparator;
import org.springframework.security.config.ConfigUtils.FilterChainList;
import org.springframework.security.util.FilterChainProxy;

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
        FilterChainList filterList = (FilterChainList) beanFactory.getBean(BeanIds.FILTER_LIST);
        
        List filters = new ArrayList(filterList.getFilters());
        Collections.sort(filters, new OrderComparator());
        // Note that this returns a copy
        Map filterMap = filterChainProxy.getFilterChainMap();
        filterMap.put(filterChainProxy.getMatcher().getUniversalMatchPattern(), filters);
        filterChainProxy.setFilterChainMap(filterMap);

        logger.info("FilterChainProxy: " + filterChainProxy);        

        return bean;
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.beanFactory = (ListableBeanFactory) beanFactory;
	}
}
