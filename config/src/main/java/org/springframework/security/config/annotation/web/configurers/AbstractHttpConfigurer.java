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

package org.springframework.security.config.annotation.web.configurers;

import java.util.function.Consumer;

import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * Adds a convenient base class for {@link SecurityConfigurer} instances that operate on
 * {@link HttpSecurity}.
 *
 * @author Rob Winch
 * @author Steve Riesenberg
 */
public abstract class AbstractHttpConfigurer<T extends AbstractHttpConfigurer<T, B>, B extends HttpSecurityBuilder<B>>
		extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, B> {

	/**
	 * Disables the {@link AbstractHttpConfigurer} by removing it. After doing so a fresh
	 * version of the configuration can be applied.
	 * @return the {@link HttpSecurityBuilder} for additional customizations
	 */
	@SuppressWarnings("unchecked")
	public B disable() {
		getBuilder().removeConfigurer(getClass());
		return getBuilder();
	}

	/**
	 * Adds an {@link ObjectPostProcessor} to post process objects created by this
	 * configurer.
	 * @param objectPostProcessor the {@link ObjectPostProcessor} providing access to the
	 * {@code object} to be post processed
	 * @return the {@link HttpSecurityBuilder} for additional customizations
	 */
	@SuppressWarnings("unchecked")
	public T withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
		addObjectPostProcessor(objectPostProcessor);
		return (T) this;
	}

	/**
	 * Adds an {@link ObjectPostProcessor} to post process objects created by this
	 * configurer.
	 * @param oppClass The target class of the {@code object} to be post processed
	 * @param objectPostProcessor the {@link Consumer} providing access to the
	 * {@code object} to be post processed
	 * @return the {@link HttpSecurityBuilder} for additional customizations
	 */
	@SuppressWarnings("unchecked")
	public <P> T withObjectPostProcessor(Class<P> oppClass, Consumer<P> objectPostProcessor) {
		addObjectPostProcessor(oppClass, objectPostProcessor);
		return (T) this;
	}

}
