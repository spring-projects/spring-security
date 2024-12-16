/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.config.annotation.web.socket;

import io.micrometer.observation.ObservationRegistry;

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.ClassUtils;

/**
 * Used by {@link EnableWebSocketSecurity} to conditionally import observation
 * configuration when {@link ObservationRegistry} is present.
 *
 * @author Josh Cummings
 * @since 6.4
 */
class WebSocketObservationImportSelector implements ImportSelector {

	private static final boolean observabilityPresent;

	static {
		ClassLoader classLoader = WebSocketObservationImportSelector.class.getClassLoader();
		observabilityPresent = ClassUtils.isPresent("io.micrometer.observation.ObservationRegistry", classLoader);
	}

	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		if (!observabilityPresent) {
			return new String[0];
		}
		return new String[] { WebSocketObservationConfiguration.class.getName() };
	}

}
