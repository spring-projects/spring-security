/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.access.annotation;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;

import org.springframework.security.access.SecurityConfig;

/**
 * Security config applicable as a JSR 250 annotation attribute.
 *
 * @author Ryan Heaton
 * @since 2.0
 */
public class Jsr250SecurityConfig extends SecurityConfig {

	public static final Jsr250SecurityConfig PERMIT_ALL_ATTRIBUTE = new Jsr250SecurityConfig(PermitAll.class.getName());

	public static final Jsr250SecurityConfig DENY_ALL_ATTRIBUTE = new Jsr250SecurityConfig(DenyAll.class.getName());

	public Jsr250SecurityConfig(String role) {
		super(role);
	}

}
