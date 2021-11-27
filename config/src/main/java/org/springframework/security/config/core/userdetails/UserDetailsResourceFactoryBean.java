/*
 * Copyright 2002-2018 the original author or authors.
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

import java.io.InputStream;
import java.util.Collection;
import java.util.Map;
import java.util.Properties;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.util.InMemoryResource;
import org.springframework.util.Assert;

/**
 * Parses a Resource that is a Properties file in the format of:
 *
 * <code>
 * username=password[,enabled|disabled],roles...
 * </code>
 *
 * The enabled and disabled properties are optional with enabled being the default. For
 * example:
 *
 * <code>
 * user=password,ROLE_USER
 * admin=secret,ROLE_USER,ROLE_ADMIN
 * disabled_user=does_not_matter,disabled,ROLE_USER
 * </code>
 *
 * @author Rob Winch
 * @since 5.0
 */
public class UserDetailsResourceFactoryBean implements ResourceLoaderAware, FactoryBean<Collection<UserDetails>> {

	private ResourceLoader resourceLoader = new DefaultResourceLoader();

	private String resourceLocation;

	private Resource resource;

	@Override
	public void setResourceLoader(ResourceLoader resourceLoader) {
		Assert.notNull(resourceLoader, "resourceLoader cannot be null");
		this.resourceLoader = resourceLoader;
	}

	@Override
	public Collection<UserDetails> getObject() throws Exception {
		Properties userProperties = new Properties();
		Resource resource = getPropertiesResource();
		try (InputStream in = resource.getInputStream()) {
			userProperties.load(in);
		}
		return new UserDetailsMapFactoryBean((Map) userProperties).getObject();
	}

	@Override
	public Class<?> getObjectType() {
		return Collection.class;
	}

	/**
	 * Sets the location of a Resource that is a Properties file in the format defined in
	 * {@link UserDetailsResourceFactoryBean}.
	 * @param resourceLocation the location of the properties file that contains the users
	 * (i.e. "classpath:users.properties")
	 */
	public void setResourceLocation(String resourceLocation) {
		this.resourceLocation = resourceLocation;
	}

	/**
	 * Sets a Resource that is a Properties file in the format defined in
	 * {@link UserDetailsResourceFactoryBean}.
	 * @param resource the Resource to use
	 */
	public void setResource(Resource resource) {
		this.resource = resource;
	}

	private Resource getPropertiesResource() {
		Resource result = this.resource;
		if (result == null && this.resourceLocation != null) {
			result = this.resourceLoader.getResource(this.resourceLocation);
		}
		Assert.notNull(result, "resource cannot be null if resourceLocation is null");
		return result;
	}

	/**
	 * Create a UserDetailsResourceFactoryBean with the location of a Resource that is a
	 * Properties file in the format defined in {@link UserDetailsResourceFactoryBean}.
	 * @param resourceLocation the location of the properties file that contains the users
	 * (i.e. "classpath:users.properties")
	 * @return the UserDetailsResourceFactoryBean
	 */
	public static UserDetailsResourceFactoryBean fromResourceLocation(String resourceLocation) {
		UserDetailsResourceFactoryBean result = new UserDetailsResourceFactoryBean();
		result.setResourceLocation(resourceLocation);
		return result;
	}

	/**
	 * Create a UserDetailsResourceFactoryBean with a Resource that is a Properties file
	 * in the format defined in {@link UserDetailsResourceFactoryBean}.
	 * @param propertiesResource the Resource that is a properties file that contains the
	 * users
	 * @return the UserDetailsResourceFactoryBean
	 */
	public static UserDetailsResourceFactoryBean fromResource(Resource propertiesResource) {
		UserDetailsResourceFactoryBean result = new UserDetailsResourceFactoryBean();
		result.setResource(propertiesResource);
		return result;
	}

	/**
	 * Creates a UserDetailsResourceFactoryBean with a resource from the provided String
	 * @param users the string representing the users
	 * @return the UserDetailsResourceFactoryBean
	 */
	public static UserDetailsResourceFactoryBean fromString(String users) {
		InMemoryResource resource = new InMemoryResource(users);
		return fromResource(resource);
	}

}
