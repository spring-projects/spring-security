/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.crypto.password;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * A {@code PasswordEncoder} implementation that uses passwordEncoder like follow:
 * <ul>
 * <li>1. Find from the {@link #applicationContext}.</li>
 * <li>2. Create by {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}.</li>
 * <ul/>
 *
 * @author Rob Winch
 * @author He Bo
 */
public class LazyPasswordEncoder implements PasswordEncoder {
	private ApplicationContext applicationContext;
	private volatile PasswordEncoder passwordEncoder;

	private final Object monitor = new Object();

	public LazyPasswordEncoder(ApplicationContext applicationContext) {
		this.applicationContext = applicationContext;
	}

	@Override
	public String encode(CharSequence rawPassword) {
		return getPasswordEncoder().encode(rawPassword);
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return getPasswordEncoder().matches(rawPassword, encodedPassword);
	}

	@Override
	public boolean upgradeEncoding(String encodedPassword) {
		return getPasswordEncoder().upgradeEncoding(encodedPassword);
	}

	private PasswordEncoder getPasswordEncoder() {
		if (this.passwordEncoder != null) {
			return this.passwordEncoder;
		}

		synchronized (monitor) {
			if (this.passwordEncoder != null) {
				return passwordEncoder;
			}
			this.passwordEncoder = getBeanOrNull(PasswordEncoder.class);
			if (this.passwordEncoder == null) {
				this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			}
		}
		return this.passwordEncoder;
	}

	private <T> T getBeanOrNull(Class<T> type) {
		try {
			return this.applicationContext.getBean(type);
		} catch (NoSuchBeanDefinitionException notFound) {
			return null;
		}
	}

	@Override
	public String toString() {
		return getPasswordEncoder().toString();
	}
}
