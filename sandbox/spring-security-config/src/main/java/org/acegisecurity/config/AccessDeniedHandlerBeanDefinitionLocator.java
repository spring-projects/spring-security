/**
 * 
 */
package org.acegisecurity.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.acegisecurity.ui.AccessDeniedHandler;
import org.acegisecurity.ui.ExceptionTranslationFilter;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.util.Assert;

/**
 * @author vpuri
 * 
 */
public class AccessDeniedHandlerBeanDefinitionLocator implements BeanFactoryPostProcessor {

	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

		Map m = beanFactory.getBeansOfType(AccessDeniedHandler.class);

		List l = new ArrayList(m.values());
		
		

		if (m.size() > 1) {
			throw new IllegalArgumentException(
					"More than one AccessDeniedHandler beans detected please refer to the one using "
							+ " [ accessDeniedBeanRef  ] " + "attribute");
		}
		else if (m.size() == 1) {
			// use this
			String[] names = beanFactory.getBeanNamesForType(ExceptionTranslationFilter.class);
			Assert.notEmpty(names, "No bean of type ExceptionTranslationFilter found in ApplicationContext");
			RootBeanDefinition definition = (RootBeanDefinition) beanFactory.getBeanDefinition(names[0]);
			Assert.isAssignable(AccessDeniedHandler.class, l.get(0).getClass());
			definition.getPropertyValues().addPropertyValue("accessDeniedHandler", l.get(0));
		}
		else {
			// use the default one for now
		}

	}
}
