/*
 * Copyright 2002-2017 the original author or authors.
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

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.AdviceModeImportSelector;
import org.springframework.context.annotation.AutoProxyRegistrar;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Rob Winch
 * @since 5.0
 */
class ReactiveMethodSecuritySelector extends AdviceModeImportSelector<EnableReactiveMethodSecurity> {

	@Override
	protected String[] selectImports(AdviceMode adviceMode) {
		switch (adviceMode) {
		case PROXY:
			return getProxyImports();
		default:
			throw new IllegalStateException("AdviceMode " + adviceMode + " is not supported");
		}
	}

	/**
	 * Return the imports to use if the {@link AdviceMode} is set to
	 * {@link AdviceMode#PROXY}.
	 * <p>
	 * Take care of adding the necessary JSR-107 import if it is available.
	 */
	private String[] getProxyImports() {
		List<String> result = new ArrayList<>();
		result.add(AutoProxyRegistrar.class.getName());
		result.add(ReactiveMethodSecurityConfiguration.class.getName());
		return result.toArray(new String[0]);
	}

}
