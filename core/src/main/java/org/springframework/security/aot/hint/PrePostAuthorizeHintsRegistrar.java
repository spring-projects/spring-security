/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.aot.hint;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.aot.hint.RuntimeHints;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.RegisteredBean;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * A {@link SecurityHintsRegistrar} that scans all beans for methods that use
 * {@link PreAuthorize} or {@link PostAuthorize} and registers appropriate hints for the
 * annotations.
 *
 * @author Marcus da Coregio
 * @since 6.4
 * @see SecurityHintsAotProcessor
 * @see PrePostAuthorizeExpressionBeanHintsRegistrar
 */
public final class PrePostAuthorizeHintsRegistrar implements SecurityHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, ConfigurableListableBeanFactory beanFactory) {
		List<Class<?>> beans = Arrays.stream(beanFactory.getBeanDefinitionNames())
			.map((beanName) -> RegisteredBean.of(beanFactory, beanName).getBeanClass())
			.collect(Collectors.toList());
		new PrePostAuthorizeExpressionBeanHintsRegistrar(beans).registerHints(hints, beanFactory);
	}

}
