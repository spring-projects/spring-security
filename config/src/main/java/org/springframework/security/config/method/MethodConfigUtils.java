/*
 * Copyright 2002-2012 the original author or authors.
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
package org.springframework.security.config.method;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.BeanIds;

/**
 * Utility methods used internally by the Spring Security namespace configuration code.
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @author Rob Winch
 */
abstract class MethodConfigUtils {

	@SuppressWarnings("unchecked")
	static void registerDefaultMethodAccessManagerIfNecessary(ParserContext parserContext) {
		if (!parserContext.getRegistry().containsBeanDefinition(BeanIds.METHOD_ACCESS_MANAGER)) {
			parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_ACCESS_MANAGER,
					createAccessManagerBean(RoleVoter.class, AuthenticatedVoter.class));
		}
	}

	@SuppressWarnings("unchecked")
	private static RootBeanDefinition createAccessManagerBean(Class<? extends AccessDecisionVoter>... voters) {
		ManagedList defaultVoters = new ManagedList(voters.length);

		for (Class<? extends AccessDecisionVoter> voter : voters) {
			defaultVoters.add(new RootBeanDefinition(voter));
		}

		BeanDefinitionBuilder accessMgrBuilder = BeanDefinitionBuilder.rootBeanDefinition(AffirmativeBased.class);
		accessMgrBuilder.addConstructorArgValue(defaultVoters);
		return (RootBeanDefinition) accessMgrBuilder.getBeanDefinition();
	}

}
