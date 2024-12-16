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

import org.springframework.aot.hint.RuntimeHints;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;

/**
 * An interface for registering AOT hints.
 *
 * <p>
 * This interface is helpful because it allows for basing hints on Spring Security's
 * infrastructural beans like so:
 *
 * <pre>
 *	&#064;Bean
 *	&#064;Role(BeanDefinition.ROLE_INFRASTRUCTURE)
 *	static SecurityHintsRegistrar proxyThese(AuthorizationProxyFactory proxyFactory) {
 *		return new AuthorizationProxyFactoryHintsRegistrar(proxyFactory, MyClass.class);
 *	}
 * </pre>
 *
 * <p>
 * The collection of beans that implement {@link SecurityHintsRegistrar} are serially
 * invoked by {@link SecurityHintsAotProcessor}, a
 * {@link org.springframework.beans.factory.aot.BeanFactoryInitializationAotProcessor}.
 *
 * <p>
 * Since this is used in a
 * {@link org.springframework.beans.factory.aot.BeanFactoryInitializationAotProcessor},
 * the Spring Framework recommendation to only depend on infrastructural beans applies.
 *
 * <p>
 * If you do not need Security's infrastructural beans, consider either implementing
 * {@link org.springframework.aot.hint.RuntimeHintsRegistrar} or another AOT component as
 * indicated in the Spring Framework AOT reference documentation.
 *
 * @author Josh Cummings
 * @since 6.4
 * @see AuthorizeReturnObjectHintsRegistrar
 * @see SecurityHintsAotProcessor
 */
public interface SecurityHintsRegistrar {

	/**
	 * Register hints after preparing them through Security's infrastructural beans
	 * @param hints the registration target for any AOT hints
	 * @param beanFactory the bean factory
	 */
	void registerHints(RuntimeHints hints, ConfigurableListableBeanFactory beanFactory);

}
