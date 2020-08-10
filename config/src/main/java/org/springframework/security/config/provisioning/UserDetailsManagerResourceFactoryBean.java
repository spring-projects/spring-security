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

package org.springframework.security.config.provisioning;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.core.userdetails.UserDetailsResourceFactoryBean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.util.InMemoryResource;

import java.util.Collection;

/**
 * Constructs an {@link InMemoryUserDetailsManager} from a resource using
 * {@link UserDetailsResourceFactoryBean}.
 *
 * @author Rob Winch
 * @since 5.0
 * @see UserDetailsResourceFactoryBean
 */
public class UserDetailsManagerResourceFactoryBean
		implements ResourceLoaderAware, FactoryBean<InMemoryUserDetailsManager> {

	private UserDetailsResourceFactoryBean userDetails = new UserDetailsResourceFactoryBean();

	@Override
	public InMemoryUserDetailsManager getObject() throws Exception {
		Collection<UserDetails> users = userDetails.getObject();
		return new InMemoryUserDetailsManager(users);
	}

	@Override
	public Class<?> getObjectType() {
		return InMemoryUserDetailsManager.class;
	}

	@Override
	public void setResourceLoader(ResourceLoader resourceLoader) {
		userDetails.setResourceLoader(resourceLoader);
	}

	/**
	 * Sets the location of a Resource that is a Properties file in the format defined in
	 * {@link UserDetailsResourceFactoryBean}.
	 * @param resourceLocation the location of the properties file that contains the users
	 * (i.e. "classpath:users.properties")
	 */
	public void setResourceLocation(String resourceLocation) {
		this.userDetails.setResourceLocation(resourceLocation);
	}

	/**
	 * Sets a Resource that is a Properties file in the format defined in
	 * {@link UserDetailsResourceFactoryBean}.
	 * @param resource the Resource to use
	 */
	public void setResource(Resource resource) {
		this.userDetails.setResource(resource);
	}

	/**
	 * Create a UserDetailsManagerResourceFactoryBean with the location of a Resource that
	 * is a Properties file in the format defined in
	 * {@link UserDetailsResourceFactoryBean}.
	 * @param resourceLocation the location of the properties file that contains the users
	 * (i.e. "classpath:users.properties")
	 * @return the UserDetailsManagerResourceFactoryBean
	 */
	public static UserDetailsManagerResourceFactoryBean fromResourceLocation(String resourceLocation) {
		UserDetailsManagerResourceFactoryBean result = new UserDetailsManagerResourceFactoryBean();
		result.setResourceLocation(resourceLocation);
		return result;
	}

	/**
	 * Create a UserDetailsManagerResourceFactoryBean with a Resource that is a Properties
	 * file in the format defined in {@link UserDetailsResourceFactoryBean}.
	 * @param resource the Resource that is a properties file that contains the users
	 * @return the UserDetailsManagerResourceFactoryBean
	 */
	public static UserDetailsManagerResourceFactoryBean fromResource(Resource resource) {
		UserDetailsManagerResourceFactoryBean result = new UserDetailsManagerResourceFactoryBean();
		result.setResource(resource);
		return result;
	}

	/**
	 * Create a UserDetailsManagerResourceFactoryBean with a String that is in the format
	 * defined in {@link UserDetailsResourceFactoryBean}.
	 * @param users the users in the format defined in
	 * {@link UserDetailsResourceFactoryBean}
	 * @return the UserDetailsManagerResourceFactoryBean
	 */
	public static UserDetailsManagerResourceFactoryBean fromString(String users) {
		UserDetailsManagerResourceFactoryBean result = new UserDetailsManagerResourceFactoryBean();
		result.setResource(new InMemoryResource(users));
		return result;
	}

}
