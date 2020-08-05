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
package org.springframework.security.config.annotation.authentication.configuration;

import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

/**
 * A {@link SecurityConfigurer} that can be exposed as a bean to configure the global
 * {@link AuthenticationManagerBuilder}. Beans of this type are automatically used by
 * {@link AuthenticationConfiguration} to configure the global
 * {@link AuthenticationManagerBuilder}.
 *
 * @since 5.0
 * @author Rob Winch
 */
@Order(100)
public abstract class GlobalAuthenticationConfigurerAdapter
		implements SecurityConfigurer<AuthenticationManager, AuthenticationManagerBuilder> {

	public void init(AuthenticationManagerBuilder auth) throws Exception {
	}

	public void configure(AuthenticationManagerBuilder auth) throws Exception {
	}

}
