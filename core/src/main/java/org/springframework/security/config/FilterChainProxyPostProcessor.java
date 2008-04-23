package org.springframework.security.config;

import java.util.ArrayList;
import java.util.Collections;
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
        
        logger.info("Checking sorted filter chain: " + filters);
        
        for(int i=0; i < filters.size(); i++) {
            Ordered filter = (Ordered)filters.get(i);

            if (i > 0) {
                Ordered previous = (Ordered)filters.get(i-1);
                if (filter.getOrder() == previous.getOrder()) {
                    throw new SecurityConfigurationException("Filters '" + unwrapFilter(filter) + "' and '" + 
                            unwrapFilter(previous) + "' have the same 'order' value. When using custom filters, " +
                            		"please make sure the positions do not conflict with default filters. " +
                            		"Alternatively you can disable the default filters by removing the corresponding " +
                            		"child elements from <http> and not avoiding the use of <http auto-config='true'>.");
                }
            }
        }

        logger.info("Filter chain...");        
        for(int i=0; i < filters.size(); i++) {
        // Remove the ordered wrapper from the filter and put it back in the chain at the same position.
            Filter filter = unwrapFilter(filters.get(i));
            logger.info("[" + i + "] - " + filter);            
            filters.set(i, filter);
        }
        
        // Note that this returns a copy
        Map filterMap = filterChainProxy.getFilterChainMap();
        filterMap.put(filterChainProxy.getMatcher().getUniversalMatchPattern(), filters);
        filterChainProxy.setFilterChainMap(filterMap);

        logger.info("FilterChainProxy: " + filterChainProxy);        

        return bean;
    }
    
    /** 
     * Returns the delegate filter of a wrapper, or the unchanged filter if it isn't wrapped. 
     */
    private Filter unwrapFilter(Object filter) {
        if (filter instanceof OrderedFilterBeanDefinitionDecorator.OrderedFilterDecorator) {
            return ((OrderedFilterBeanDefinitionDecorator.OrderedFilterDecorator)filter).getDelegate();
        }
        
        return (Filter) filter;
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.beanFactory = (ListableBeanFactory) beanFactory;
	}
}
