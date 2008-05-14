package org.springframework.security.config;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.util.Assert;

/**
 * 
 * @author Luke Taylor
 * @since 2.0.2
 */
public class EntryPointInjectionBeanPostProcessor implements BeanPostProcessor, BeanFactoryAware {
    private final Log logger = LogFactory.getLog(getClass());
    private ConfigurableListableBeanFactory beanFactory;	

	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (!BeanIds.EXCEPTION_TRANSLATION_FILTER.equals(beanName)) {
        	return bean;
        }
        
        logger.info("Selecting AuthenticationEntryPoint for use in ExceptionTranslationFilter");
        
        ExceptionTranslationFilter etf = (ExceptionTranslationFilter) beanFactory.getBean(BeanIds.EXCEPTION_TRANSLATION_FILTER); 

        Object entryPoint = null;
        
        if (beanFactory.containsBean(BeanIds.MAIN_ENTRY_POINT)) {
            entryPoint = beanFactory.getBean(BeanIds.MAIN_ENTRY_POINT);
            logger.info("Using main configured AuthenticationEntryPoint.");
        } else {
            Map entryPoints = beanFactory.getBeansOfType(AuthenticationEntryPoint.class);
            Assert.isTrue(entryPoints.size() != 0, "No AuthenticationEntryPoint instances defined");
            Assert.isTrue(entryPoints.size() == 1, "More than one AuthenticationEntryPoint defined in context");
            entryPoint = entryPoints.values().toArray()[0];
        }
        
        logger.info("Using bean '" + entryPoint + "' as the entry point.");
        etf.setAuthenticationEntryPoint((AuthenticationEntryPoint) entryPoint);
		
		return bean;
	}	
	
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.beanFactory = (ConfigurableListableBeanFactory) beanFactory;
	}
}
