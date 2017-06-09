/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.config.provisioning;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.core.userdetails.UserDetailsResourceFactoryBean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.Collection;

/**
 * Constructs an {@link InMemoryUserDetailsManager} from a resource using {@link UserDetailsResourceFactoryBean}.
 *
 * @author Rob Winch
 * @since 5.0
 * @see UserDetailsResourceFactoryBean
 */
public class UserDetailsManagerResourceFactoryBean implements ResourceLoaderAware, FactoryBean<InMemoryUserDetailsManager> {
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
	 * Sets a the location of a Resource that is a Properties file in the format defined in {@link UserDetailsResourceFactoryBean}
	 *
	 * @param propertiesResourceLocation the location of the properties file that contains the users (i.e. "classpath:users.properties")
	 * @return the UserDetailsResourceFactoryBean
	 */
	public void setPropertiesResourceLocation(String propertiesResourceLocation) {
		this.userDetails.setPropertiesResourceLocation(propertiesResourceLocation);
	}

	/**
	 * Sets a a Resource that is a Properties file in the format defined in {@link UserDetailsResourceFactoryBean}
	 *
	 * @param propertiesResource the Resource to use
	 */
	public void setPropertiesResource(Resource propertiesResource) {
		this.userDetails.setPropertiesResource(propertiesResource);
	}

	/**
	 * Create a UserDetailsServiceResourceFactoryBean with the location of a Resource that is a Properties file in the
	 * format defined in {@link UserDetailsResourceFactoryBean}
	 *
	 * @param propertiesResourceLocation the location of the properties file that contains the users (i.e. "classpath:users.properties")
	 * @return the UserDetailsResourceFactoryBean
	 */
	public static UserDetailsManagerResourceFactoryBean usersFromResourceLocation(String propertiesResourceLocation) {
		UserDetailsManagerResourceFactoryBean result = new UserDetailsManagerResourceFactoryBean();
		result.setPropertiesResourceLocation(propertiesResourceLocation);
		return result;
	}

	/**
	 * Create a UserDetailsServiceResourceFactoryBean with a Resource that is a Properties file in the
	 * format defined in {@link UserDetailsResourceFactoryBean}
	 *
	 * @param propertiesResource the Resource that is a properties file that contains the users
	 * @return the UserDetailsResourceFactoryBean
	 */
	public static UserDetailsManagerResourceFactoryBean usersFromResource(Resource propertiesResource) {
		UserDetailsManagerResourceFactoryBean result = new UserDetailsManagerResourceFactoryBean();
		result.setPropertiesResource(propertiesResource);
		return result;
	}
}
