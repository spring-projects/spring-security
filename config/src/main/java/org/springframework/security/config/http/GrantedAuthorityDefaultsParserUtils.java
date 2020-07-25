/*
 * Copyright 2012-2018 the original author or authors.
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

package org.springframework.security.config.http;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.config.core.GrantedAuthorityDefaults;

/**
 * @author Rob Winch
 * @since 4.2
 */
final class GrantedAuthorityDefaultsParserUtils {

	private GrantedAuthorityDefaultsParserUtils() {
	}

	static RootBeanDefinition registerWithDefaultRolePrefix(ParserContext pc,
			Class<? extends AbstractGrantedAuthorityDefaultsBeanFactory> beanFactoryClass) {
		RootBeanDefinition beanFactoryDefinition = new RootBeanDefinition(beanFactoryClass);
		String beanFactoryRef = pc.getReaderContext().generateBeanName(beanFactoryDefinition);
		pc.getRegistry().registerBeanDefinition(beanFactoryRef, beanFactoryDefinition);

		RootBeanDefinition bean = new RootBeanDefinition();
		bean.setFactoryBeanName(beanFactoryRef);
		bean.setFactoryMethodName("getBean");
		return bean;
	}

	static abstract class AbstractGrantedAuthorityDefaultsBeanFactory implements ApplicationContextAware {

		protected String rolePrefix = "ROLE_";

		@Override
		public final void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
			String[] grantedAuthorityDefaultsBeanNames = applicationContext
					.getBeanNamesForType(GrantedAuthorityDefaults.class);
			if (grantedAuthorityDefaultsBeanNames.length == 1) {
				GrantedAuthorityDefaults grantedAuthorityDefaults = applicationContext
						.getBean(grantedAuthorityDefaultsBeanNames[0], GrantedAuthorityDefaults.class);
				this.rolePrefix = grantedAuthorityDefaults.getRolePrefix();
			}
		}

		abstract Object getBean();

	}

}
