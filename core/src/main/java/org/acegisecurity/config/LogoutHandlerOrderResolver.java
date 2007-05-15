/**
 * 
 */
package org.acegisecurity.config;

import java.util.Collections;
import java.util.List;

import org.acegisecurity.ui.logout.LogoutFilter;
import org.acegisecurity.ui.logout.LogoutHandler;
import org.acegisecurity.ui.logout.SecurityContextLogoutHandler;
import org.acegisecurity.ui.rememberme.TokenBasedRememberMeServices;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.ConstructorArgumentValues.ValueHolder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;

/**
 * @author vpuri
 * @since
 */
public class LogoutHandlerOrderResolver implements BeanFactoryPostProcessor {

	// ~ Methods
	// ================================================================================================

	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
		// If LogoutFilter does not have setHandlers populated, introspect app
		// ctx for LogoutHandlers, using Ordered (if present, otherwise assume
		// Integer.MAX_VALUE)
		String[] names = beanFactory.getBeanNamesForType(LogoutFilter.class);
		RootBeanDefinition definition = (RootBeanDefinition) beanFactory.getBeanDefinition(names[0]);
		ValueHolder holder = getHandlersIfConfigured(beanFactory, definition);
		if (holder == null) {
			// intropect the appcontext for registerd LogoutHandler
			List logoutHandlers = retrieveAllLogoutHandlers(beanFactory);
			definition.getConstructorArgumentValues().addIndexedArgumentValue(1, logoutHandlers);
		}
	}

	/**
	 * 
	 * @param beanFactory
	 * @param definition
	 * @return
	 */
	private ValueHolder getHandlersIfConfigured(ConfigurableListableBeanFactory beanFactory,
			RootBeanDefinition definition) {
		// there should be only one LogoutFilter
		return definition.getConstructorArgumentValues().getArgumentValue(1, null);

	}

	/**
	 * 
	 * @param beanFactory
	 * @return
	 */
	private List retrieveAllLogoutHandlers(ConfigurableListableBeanFactory beanFactory) {
		String[] names = beanFactory.getBeanNamesForType(LogoutHandler.class);
		ManagedList list = new ManagedList();

		for (int i = 0, n = names.length; i < n; i++) {
			RootBeanDefinition definition = (RootBeanDefinition) beanFactory.getBeanDefinition(names[i]);

			if (Ordered.class.isAssignableFrom(definition.getBeanClass())) {
				definition.getPropertyValues().addPropertyValue("order", getOrder(definition.getBeanClass()));
				list.add(definition);
			}
		}
		Collections.sort(list, new OrderComparator());
		return list;
	}

	private int getOrder(Class clazz) {
		if (clazz.getName().equals(TokenBasedRememberMeServices.class.getName())) {
			return 0;
		}
		if (clazz.getName().equals(SecurityContextLogoutHandler.class.getName())) {
			return 1;
		}
		return Integer.MAX_VALUE;
	}

}
