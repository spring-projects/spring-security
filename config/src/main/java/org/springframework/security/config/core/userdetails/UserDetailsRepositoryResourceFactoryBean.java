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

package org.springframework.security.config.core.userdetails;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.userdetails.MapUserDetailsRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * Constructs an {@link MapUserDetailsRepository} from a resource using {@link UserDetailsResourceFactoryBean}.
 *
 * @author Rob Winch
 * @since 5.0
 * @see UserDetailsResourceFactoryBean
 */
public class UserDetailsRepositoryResourceFactoryBean implements ResourceLoaderAware, FactoryBean<MapUserDetailsRepository> {
	private UserDetailsResourceFactoryBean userDetails = new UserDetailsResourceFactoryBean();

	@Override
	public MapUserDetailsRepository getObject() throws Exception {
		Collection<UserDetails> users = userDetails.getObject();
		return new MapUserDetailsRepository(users);
	}

	@Override
	public Class<?> getObjectType() {
		return MapUserDetailsRepository.class;
	}

	@Override
	public void setResourceLoader(ResourceLoader resourceLoader) {
		userDetails.setResourceLoader(resourceLoader);
	}

	/**
	 * Sets a the location of a Resource that is a Properties file in the format defined in {@link UserDetailsResourceFactoryBean}
	 *
	 * @param resourceLocation the location of the properties file that contains the users (i.e. "classpath:users.properties")
	 * @return the UserDetailsResourceFactoryBean
	 */
	public void setResourceLocation(String resourceLocation) {
		this.userDetails.setResourceLocation(resourceLocation);
	}

	/**
	 * Sets a a Resource that is a Properties file in the format defined in {@link UserDetailsResourceFactoryBean}
	 *
	 * @param resource the Resource to use
	 */
	public void setResource(Resource resource) {
		this.userDetails.setResource(resource);
	}

	/**
	 * Create a UserDetailsRepositoryResourceFactoryBean with the location of a Resource that is a Properties file in the
	 * format defined in {@link UserDetailsResourceFactoryBean}
	 *
	 * @param resourceLocatiton the location of the properties file that contains the users (i.e. "classpath:users.properties")
	 * @return the UserDetailsResourceFactoryBean
	 */
	public static UserDetailsRepositoryResourceFactoryBean fromResourceLocation(String resourceLocatiton) {
		UserDetailsRepositoryResourceFactoryBean result = new UserDetailsRepositoryResourceFactoryBean();
		result.setResourceLocation(resourceLocatiton);
		return result;
	}

	/**
	 * Create a UserDetailsRepositoryResourceFactoryBean with a Resource that is a Properties file in the
	 * format defined in {@link UserDetailsResourceFactoryBean}
	 *
	 * @param propertiesResource the Resource that is a properties file that contains the users
	 * @return the UserDetailsResourceFactoryBean
	 */
	public static UserDetailsRepositoryResourceFactoryBean fromResource(Resource propertiesResource) {
		UserDetailsRepositoryResourceFactoryBean result = new UserDetailsRepositoryResourceFactoryBean();
		result.setResource(propertiesResource);
		return result;
	}
}
