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

package org.springframework.security.config.annotation.method.configuration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.AdviceModeImportSelector;
import org.springframework.context.annotation.AutoProxyRegistrar;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.lang.NonNull;

/**
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @since 5.0
 */
class ReactiveMethodSecuritySelector implements ImportSelector {

	private final ImportSelector autoProxy = new AutoProxyRegistrarSelector();

	@Override
	public String[] selectImports(AnnotationMetadata importMetadata) {
		if (!importMetadata.hasAnnotation(EnableReactiveMethodSecurity.class.getName())) {
			return new String[0];
		}
		EnableReactiveMethodSecurity annotation = importMetadata.getAnnotations()
				.get(EnableReactiveMethodSecurity.class).synthesize();
		List<String> imports = new ArrayList<>(Arrays.asList(this.autoProxy.selectImports(importMetadata)));
		if (annotation.useAuthorizationManager()) {
			imports.add(ReactiveAuthorizationManagerMethodSecurityConfiguration.class.getName());
		}
		else {
			imports.add(ReactiveMethodSecurityConfiguration.class.getName());
		}
		return imports.toArray(new String[0]);
	}

	private static final class AutoProxyRegistrarSelector
			extends AdviceModeImportSelector<EnableReactiveMethodSecurity> {

		private static final String[] IMPORTS = new String[] { AutoProxyRegistrar.class.getName() };

		@Override
		protected String[] selectImports(@NonNull AdviceMode adviceMode) {
			if (adviceMode == AdviceMode.PROXY) {
				return IMPORTS;
			}
			throw new IllegalStateException("AdviceMode " + adviceMode + " is not supported");
		}

	}

}
