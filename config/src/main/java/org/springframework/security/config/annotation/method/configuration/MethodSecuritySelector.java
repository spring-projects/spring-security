/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.annotation.method.configuration;

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.AdviceModeImportSelector;
import org.springframework.context.annotation.AutoProxyRegistrar;

/**
 * Dynamically determines which imports to include using the {@link EnableMethodSecurity}
 * annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.5
 */
final class MethodSecuritySelector extends AdviceModeImportSelector<EnableMethodSecurity> {

	@Override
	protected String[] selectImports(AdviceMode adviceMode) {
		if (adviceMode == AdviceMode.PROXY) {
			return getProxyImports();
		}
		throw new IllegalStateException("AdviceMode '" + adviceMode + "' is not supported");
	}

	private String[] getProxyImports() {
		List<String> result = new ArrayList<>();
		result.add(AutoProxyRegistrar.class.getName());
		result.add(MethodSecurityConfiguration.class.getName());
		return result.toArray(new String[0]);
	}

}
