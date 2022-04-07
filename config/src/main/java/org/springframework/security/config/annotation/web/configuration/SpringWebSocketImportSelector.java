/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.ClassUtils;

/**
 * Used by {@link EnableWebSecurity} to conditionally import
 * {@link org.springframework.security.config.annotation.web.socket.WebSocketMessageBrokerSecurityConfiguration}
 * when the AbstractWebSocketHandler is present on the classpath.
 *
 * @author Josh Cummings
 * @since 5.7
 */
class SpringWebSocketImportSelector implements ImportSelector {

	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		if (!ClassUtils.isPresent("org.springframework.web.socket.handler.AbstractWebSocketHandler",
				getClass().getClassLoader())) {
			return new String[0];
		}
		return new String[] {
				"org.springframework.security.config.annotation.web.socket.WebSocketMessageBrokerSecurityConfiguration" };
	}

}
