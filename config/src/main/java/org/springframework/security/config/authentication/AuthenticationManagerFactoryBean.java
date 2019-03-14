/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.authentication;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.BeanIds;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;

/**
 * Factory bean for the namespace AuthenticationManager, which allows a more meaningful
 * error message to be reported in the <tt>NoSuchBeanDefinitionException</tt>, if the user
 * has forgotten to declare the &lt;authentication-manager&gt; element.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class AuthenticationManagerFactoryBean implements
		FactoryBean<AuthenticationManager>, BeanFactoryAware {
	private BeanFactory bf;
	public static final String MISSING_BEAN_ERROR_MESSAGE = "Did you forget to add a global <authentication-manager> element "
			+ "to your configuration (with child <authentication-provider> elements)? Alternatively you can use the "
			+ "authentication-manager-ref attribute on your <http> and <global-method-security> elements.";

	public AuthenticationManager getObject() throws Exception {
		try {
			return (AuthenticationManager) bf.getBean(BeanIds.AUTHENTICATION_MANAGER);
		}
		catch (NoSuchBeanDefinitionException e) {
			if (!BeanIds.AUTHENTICATION_MANAGER.equals(e.getBeanName())) {
				throw e;
			}

			UserDetailsService uds = getBeanOrNull(UserDetailsService.class);
			if (uds == null) {
				throw new NoSuchBeanDefinitionException(BeanIds.AUTHENTICATION_MANAGER,
					MISSING_BEAN_ERROR_MESSAGE);
			}

			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(uds);
			PasswordEncoder passwordEncoder = getBeanOrNull(PasswordEncoder.class);
			if (passwordEncoder != null) {
				provider.setPasswordEncoder(passwordEncoder);
			}
			provider.afterPropertiesSet();
			return new ProviderManager(Arrays.<AuthenticationProvider> asList(provider));
		}
	}

	public Class<? extends AuthenticationManager> getObjectType() {
		return ProviderManager.class;
	}

	public boolean isSingleton() {
		return true;
	}

	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		bf = beanFactory;
	}

	private <T> T getBeanOrNull(Class<T> type) {
		try {
			return this.bf.getBean(type);
		} catch (NoSuchBeanDefinitionException noUds) {
			return null;
		}
	}
}
