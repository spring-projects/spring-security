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
package org.springframework.security.ldap;

import javax.annotation.PreDestroy;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.ContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;

/**
 * @author Eddú Meléndez
 */
@Configuration
public class ApacheDsContainerConfig {

	private ApacheDSContainer container;

	@Bean
	ApacheDSContainer ldapContainer() throws Exception {
		this.container = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
		this.container.setPort(0);
		return this.container;
	}

	@Bean
	ContextSource contextSource(ApacheDSContainer ldapContainer) throws Exception {
		return new DefaultSpringSecurityContextSource(
				"ldap://127.0.0.1:" + ldapContainer.getLocalPort() + "/dc=springframework,dc=org");
	}

	@PreDestroy
	void shutdown() {
		this.container.stop();
	}

}
