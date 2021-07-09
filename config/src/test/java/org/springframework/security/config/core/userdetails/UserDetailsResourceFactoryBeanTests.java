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

import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.util.InMemoryResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class UserDetailsResourceFactoryBeanTests {

	@Mock
	ResourceLoader resourceLoader;

	UserDetailsResourceFactoryBean factory = new UserDetailsResourceFactoryBean();

	@Test
	public void setResourceLoaderWhenNullThenThrowsException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.factory.setResourceLoader(null))
				.withStackTraceContaining("resourceLoader cannot be null");
		// @formatter:on
	}

	@Test
	public void getObjectWhenPropertiesResourceLocationNullThenThrowsIllegalStateException() {
		this.factory.setResourceLoader(this.resourceLoader);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.factory.getObject())
				.withStackTraceContaining("resource cannot be null if resourceLocation is null");
		// @formatter:on
	}

	@Test
	public void getObjectWhenPropertiesResourceLocationSingleUserThenThrowsGetsSingleUser() throws Exception {
		this.factory.setResourceLocation("classpath:users.properties");
		Collection<UserDetails> users = this.factory.getObject();
		assertLoaded();
	}

	@Test
	public void getObjectWhenPropertiesResourceSingleUserThenThrowsGetsSingleUser() throws Exception {
		this.factory.setResource(new InMemoryResource("user=password,ROLE_USER"));
		assertLoaded();
	}

	@Test
	public void getObjectWhenInvalidUserThenThrowsMeaningfulException() {
		this.factory.setResource(new InMemoryResource("user=invalidFormatHere"));
		// @formatter:off
		assertThatIllegalStateException()
				.isThrownBy(() -> this.factory.getObject())
				.withStackTraceContaining("user")
				.withStackTraceContaining("invalidFormatHere");
		// @formatter:on
	}

	@Test
	public void getObjectWhenStringSingleUserThenGetsSingleUser() throws Exception {
		this.factory = UserDetailsResourceFactoryBean.fromString("user=password,ROLE_USER");
		assertLoaded();
	}

	private void assertLoaded() throws Exception {
		Collection<UserDetails> users = this.factory.getObject();
		// @formatter:off
		UserDetails expectedUser = User.withUsername("user")
			.password("password")
			.authorities("ROLE_USER")
			.build();
		// @formatter:on
		assertThat(users).containsExactly(expectedUser);
	}

}
