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

package org.springframework.security.config.annotation.method.configuration.issue14637;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.issue14637.domain.Entry;
import org.springframework.security.config.annotation.method.configuration.issue14637.repo.EntryRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Josh Cummings
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = { ApplicationConfig.class, SecurityConfig.class })
public class Issue14637Tests {

	@Autowired
	private EntryRepository entries;

	@Test
	@WithMockUser
	public void authenticateWhenInvalidPasswordThenBadCredentialsException() {
		Entry entry = new Entry();
		entry.setId(123L);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.entries.save(entry));
	}

}
