/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.config.BeanIds;
import org.springframework.security.ldap.server.UnboundIdContainer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Eddú Meléndez
 */
public class LdapServerBeanDefinitionParserTests {

	private ClassPathXmlApplicationContext context;

	@Before
	public void setup() {
		this.context = new ClassPathXmlApplicationContext("applicationContext-security.xml");
	}

	@After
	public void closeAppContext() {
		if (this.context != null) {
			this.context.close();
			this.context = null;
		}
	}

	@Test
	public void apacheDirectoryServerIsStartedByDefault() {
		String[] beanNames = this.context.getBeanNamesForType(UnboundIdContainer.class);
		assertThat(beanNames).hasSize(1);
		assertThat(beanNames[0]).isEqualTo(BeanIds.EMBEDDED_UNBOUNDID);
	}

}
