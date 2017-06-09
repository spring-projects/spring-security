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

package org.springframework.security.config.core.userdetails;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.security.core.userdetails.memory.UserAttributeEditor;
import org.springframework.util.Assert;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Properties;

/**
 * Parses a Resource that is a Properties file in the format of:
 *
 * <code>
 * username=password[,enabled|disabled],roles...
 * </code>
 *
 * The enabled and disabled properties are optional with enabled being the default. For example:
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
	private ResourceLoader resourceLoader;

	private String propertiesResourceLocation;

	private Resource propertiesResource;

	@Override
	public void setResourceLoader(ResourceLoader resourceLoader) {
		this.resourceLoader = resourceLoader;
	}

	@Override
	public Collection<UserDetails> getObject() throws Exception {
		Properties userProperties = new Properties();
		Resource resource = getProperitesResource();
		try(InputStream in = resource.getInputStream()){
			userProperties.load(in);
		}

		Collection<UserDetails> users = new ArrayList<>(userProperties.size());
		Enumeration<?> names = userProperties.propertyNames();
		UserAttributeEditor editor = new UserAttributeEditor();

		while (names.hasMoreElements()) {
			String name = (String) names.nextElement();
			String property = userProperties.getProperty(name);
			editor.setAsText(property);
			UserAttribute attr = (UserAttribute) editor.getValue();
			if(attr == null) {
				throw new IllegalStateException("The entry with username '" + name + "' and value '" + property + "' could not be converted to a UserDetails.");
			}
			UserDetails user = User.withUsername(name)
				.password(attr.getPassword())
				.disabled(!attr.isEnabled())
				.authorities(attr.getAuthorities())
				.build();
			users.add(user);
		}
		return users;
	}

	@Override
	public Class<?> getObjectType() {
		return Collection.class;
	}

	/**
	 * Sets a the location of a Resource that is a Properties file in the format defined in {@link UserDetailsResourceFactoryBean}
	 *
	 * @param propertiesResourceLocation the location of the properties file that contains the users (i.e. "classpath:users.properties")
	 */
	public void setPropertiesResourceLocation(String propertiesResourceLocation) {
		this.propertiesResourceLocation = propertiesResourceLocation;
	}

	/**
	 * Sets a a Resource that is a Properties file in the format defined in {@link UserDetailsResourceFactoryBean}
	 *
	 * @param propertiesResource the Resource to use
	 */
	public void setPropertiesResource(Resource propertiesResource) {
		this.propertiesResource = propertiesResource;
	}

	private Resource getProperitesResource() {
		if(propertiesResource != null) {
			return propertiesResource;
		}
		if(propertiesResourceLocation != null) {
			Assert.notNull(resourceLoader, "resourceLoader cannot be null if propertiesResource is null");
			return resourceLoader.getResource(propertiesResourceLocation);
		}
		throw new IllegalStateException("Either propertiesResource cannot be null or both resourceLoader and propertiesResourceLocation cannot be null");
	}
}
