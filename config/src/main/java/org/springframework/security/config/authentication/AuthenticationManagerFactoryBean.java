/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.Arrays;

import io.micrometer.observation.ObservationRegistry;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ObservationAuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.BeanIds;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Factory bean for the namespace AuthenticationManager, which allows a more meaningful
 * error message to be reported in the <tt>NoSuchBeanDefinitionException</tt>, if the user
 * has forgotten to declare the &lt;authentication-manager&gt; element.
 *
 * @author Luke Taylor
 * @author Ngoc Nhan
 * @since 3.0
 */
public class AuthenticationManagerFactoryBean implements FactoryBean<AuthenticationManager>, BeanFactoryAware {

	private BeanFactory bf;

	private ObservationRegistry observationRegistry = ObservationRegistry.NOOP;

	public static final String MISSING_BEAN_ERROR_MESSAGE = "Did you forget to add a global <authentication-manager> element "
			+ "to your configuration (with child <authentication-provider> elements)? Alternatively you can use the "
			+ "authentication-manager-ref attribute on your <http> and <global-method-security> elements.";

	@Override
	public AuthenticationManager getObject() throws Exception {
		try {
			return (AuthenticationManager) this.bf.getBean(BeanIds.AUTHENTICATION_MANAGER);
		}
		catch (NoSuchBeanDefinitionException ex) {
			if (!BeanIds.AUTHENTICATION_MANAGER.equals(ex.getBeanName())) {
				throw ex;
			}
			UserDetailsService uds = this.bf.getBeanProvider(UserDetailsService.class).getIfUnique();
			if (uds == null) {
				throw new NoSuchBeanDefinitionException(BeanIds.AUTHENTICATION_MANAGER, MISSING_BEAN_ERROR_MESSAGE);
			}
			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(uds);
			PasswordEncoder passwordEncoder = this.bf.getBeanProvider(PasswordEncoder.class).getIfUnique();
			if (passwordEncoder != null) {
				provider.setPasswordEncoder(passwordEncoder);
			}
			provider.afterPropertiesSet();
			ProviderManager manager = new ProviderManager(Arrays.asList(provider));
			if (this.observationRegistry.isNoop()) {
				return manager;
			}
			return new ObservationAuthenticationManager(this.observationRegistry, manager);
		}
	}

	@Override
	public Class<? extends AuthenticationManager> getObjectType() {
		return ProviderManager.class;
	}

	@Override
	public boolean isSingleton() {
		return true;
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.bf = beanFactory;
	}

	public void setObservationRegistry(ObservationRegistry observationRegistry) {
		this.observationRegistry = observationRegistry;
	}

}
