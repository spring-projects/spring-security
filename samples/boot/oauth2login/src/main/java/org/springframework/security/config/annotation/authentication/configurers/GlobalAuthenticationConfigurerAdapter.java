/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.authentication.configurers;

import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

/**
 * <b>NOTE:</b>
 * This class is here as a TEMPORARY FIX in order to force
 * <code>@ConditionalOnClass(GlobalAuthenticationConfigurerAdapter.class)</code> in
 * <code>org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration</code>.
 * <p>
 * Spring Boot M5 expects GlobalAuthenticationConfigurerAdapter to be located in package
 * <code>org.springframework.security.config.annotation.authentication.configurers</code>.
 * However, it's recently been moved to
 * <code>org.springframework.security.config.annotation.authentication.configuration</code>
 * resulting in <code>SecurityAutoConfiguration</code> <b>NOT</b> being triggered.
 * <p>
 * This class should be removed after a fix has been applied to Spring Boot M6 or RC1.
 *
 * @author Joe Grandja
 */
@Order(100)
public abstract class GlobalAuthenticationConfigurerAdapter implements
	SecurityConfigurer<AuthenticationManager, AuthenticationManagerBuilder> {

	public void init(AuthenticationManagerBuilder auth) throws Exception {
	}

	public void configure(AuthenticationManagerBuilder auth) throws Exception {
	}
}
