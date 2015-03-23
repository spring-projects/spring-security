/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.config.annotation.web.configuration;

import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.ConfigurationCondition;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.ClassUtils;

import java.util.Map;

/**
 * @author Rob Winch
 */
class OnMissingBeanCondition implements ConfigurationCondition {
	public ConfigurationPhase getConfigurationPhase() {
		return ConfigurationPhase.REGISTER_BEAN;
	}

	public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
		Map<String, Object> attrs = metadata
				.getAnnotationAttributes(ConditionalOnMissingBean.class.getName());

		Class<?> type = (Class) attrs.get("value");
		final Map<String, ?> beans = context.getBeanFactory().getBeansOfType(type);
		return beans.isEmpty();
	}
}
