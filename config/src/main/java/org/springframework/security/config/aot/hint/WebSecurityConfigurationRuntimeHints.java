/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.aot.hint;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;

/**
 * Runtime hints for
 * {@link org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration}
 *
 * @author Marcus da Coregio
 */
class WebSecurityConfigurationRuntimeHints implements RuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
		hints.reflection()
			.registerType(TypeReference
				.of("org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration$CompositeFilterChainProxy"),
					MemberCategory.INVOKE_DECLARED_CONSTRUCTORS);
		hints.reflection()
			.registerType(TypeReference.of("org.springframework.web.filter.ServletRequestPathFilter"),
					MemberCategory.INVOKE_DECLARED_CONSTRUCTORS);
	}

}
