/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.config.ldap;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ApplicationContextException;
import org.springframework.core.Ordered;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Elements;
import org.springframework.util.ClassUtils;

/**
 * Checks for the presence of a ContextSource instance. Also supplies the standard
 * reference to any unconfigured &lt;ldap-authentication-provider&gt; or
 * &lt;ldap-user-service&gt; beans. This is necessary in cases where the user has given
 * the server a specific Id, but hasn't used the server-ref attribute to link this to the
 * other ldap definitions. See SEC-799.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class ContextSourceSettingPostProcessor implements BeanFactoryPostProcessor, Ordered {

	private static final String REQUIRED_CONTEXT_SOURCE_CLASS_NAME = "org.springframework.ldap.core.support.BaseLdapPathContextSource";

	/**
	 * If set to true, a bean parser has indicated that the default context source name
	 * needs to be set
	 */
	private boolean defaultNameRequired;

	ContextSourceSettingPostProcessor() {
	}

	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory bf) throws BeansException {
		Class<?> contextSourceClass = getContextSourceClass();
		String[] sources = bf.getBeanNamesForType(contextSourceClass, false, false);
		if (sources.length == 0) {
			throw new ApplicationContextException("No BaseLdapPathContextSource instances found. Have you "
					+ "added an <" + Elements.LDAP_SERVER + " /> element to your application context? If you have "
					+ "declared an explicit bean, do not use lazy-init");
		}
		if (!bf.containsBean(BeanIds.CONTEXT_SOURCE) && this.defaultNameRequired) {
			if (sources.length > 1) {
				throw new ApplicationContextException("More than one BaseLdapPathContextSource instance found. "
						+ "Please specify a specific server id using the 'server-ref' attribute when configuring your <"
						+ Elements.LDAP_PROVIDER + "> " + "or <" + Elements.LDAP_USER_SERVICE + ">.");
			}
			bf.registerAlias(sources[0], BeanIds.CONTEXT_SOURCE);
		}
	}

	private Class<?> getContextSourceClass() throws LinkageError {
		try {
			return ClassUtils.forName(REQUIRED_CONTEXT_SOURCE_CLASS_NAME, ClassUtils.getDefaultClassLoader());
		}
		catch (ClassNotFoundException ex) {
			throw new ApplicationContextException("Couldn't locate: " + REQUIRED_CONTEXT_SOURCE_CLASS_NAME + ". "
					+ " If you are using LDAP with Spring Security, please ensure that you include the spring-ldap "
					+ "jar file in your application", ex);
		}
	}

	public void setDefaultNameRequired(boolean defaultNameRequired) {
		this.defaultNameRequired = defaultNameRequired;
	}

	@Override
	public int getOrder() {
		return LOWEST_PRECEDENCE;
	}

}
