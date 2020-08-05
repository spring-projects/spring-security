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

package org.springframework.security.config.core.userdetails;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.util.InMemoryResource;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class UserDetailsResourceFactoryBeanTests {

	@Mock
	ResourceLoader resourceLoader;

	UserDetailsResourceFactoryBean factory = new UserDetailsResourceFactoryBean();

	@Test
	public void setResourceLoaderWhenNullThenThrowsException() {
		assertThatThrownBy(() -> factory.setResourceLoader(null)).isInstanceOf(IllegalArgumentException.class)
				.hasStackTraceContaining("resourceLoader cannot be null");
	}

	@Test
	public void getObjectWhenPropertiesResourceLocationNullThenThrowsIllegalStateException() {
		factory.setResourceLoader(resourceLoader);

		assertThatThrownBy(() -> factory.getObject()).isInstanceOf(IllegalArgumentException.class)
				.hasStackTraceContaining("resource cannot be null if resourceLocation is null");
	}

	@Test
	public void getObjectWhenPropertiesResourceLocationSingleUserThenThrowsGetsSingleUser() throws Exception {
		factory.setResourceLocation("classpath:users.properties");

		Collection<UserDetails> users = factory.getObject();

		assertLoaded();
	}

	@Test
	public void getObjectWhenPropertiesResourceSingleUserThenThrowsGetsSingleUser() throws Exception {
		factory.setResource(new InMemoryResource("user=password,ROLE_USER"));

		assertLoaded();
	}

	@Test
	public void getObjectWhenInvalidUserThenThrowsMeaningfulException() {
		factory.setResource(new InMemoryResource("user=invalidFormatHere"));

		assertThatThrownBy(() -> factory.getObject()).isInstanceOf(IllegalStateException.class)
				.hasStackTraceContaining("user").hasStackTraceContaining("invalidFormatHere");
	}

	@Test
	public void getObjectWhenStringSingleUserThenGetsSingleUser() throws Exception {
		this.factory = UserDetailsResourceFactoryBean.fromString("user=password,ROLE_USER");

		assertLoaded();
	}

	private void assertLoaded() throws Exception {
		Collection<UserDetails> users = factory.getObject();
		// @formatter:off
		UserDetails expectedUser = User.withUsername("user")
			.password("password")
			.authorities("ROLE_USER")
			.build();
		// @formatter:on
		assertThat(users).containsExactly(expectedUser);
	}

}
