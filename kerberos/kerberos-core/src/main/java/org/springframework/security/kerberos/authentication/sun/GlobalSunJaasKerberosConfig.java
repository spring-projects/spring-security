/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kerberos.authentication.sun;

import org.jspecify.annotations.Nullable;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * Config for global jaas.
 *
 * @author Mike Wiesner
 * @since 1.0
 */
public class GlobalSunJaasKerberosConfig implements BeanPostProcessor, InitializingBean {

	private boolean debug = false;

	private @Nullable String krbConfLocation;

	@Override
	public void afterPropertiesSet() throws Exception {
		if (this.debug) {
			System.setProperty("sun.security.krb5.debug", "true");
		}
		if (this.krbConfLocation != null) {
			System.setProperty("java.security.krb5.conf", this.krbConfLocation);
		}

	}

	/**
	 * Enable debug logs from the Sun Kerberos Implementation. Default is false.
	 * @param debug true if debug should be enabled
	 */
	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	/**
	 * Kerberos config file location can be specified here.
	 * @param krbConfLocation the path to krb config file
	 */
	public void setKrbConfLocation(String krbConfLocation) {
		this.krbConfLocation = krbConfLocation;
	}

	// The following methods are not used here. This Bean implements only
	// BeanPostProcessor to ensure that it
	// is created before any other bean is created, because the system properties needed
	// to be set very early
	// in the startup-phase, but after the BeanFactoryPostProcessing.

	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

	@Override
	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

}
