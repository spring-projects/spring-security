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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.security.core.userdetails.memory.UserAttributeEditor;
import org.springframework.util.Assert;

/**
 * Creates a {@code Collection<UserDetails>} from a @{code Map} in the format of
 * <p>
 * <code>
 * username=password[,enabled|disabled],roles...
 * </code>
 * <p>
 * The enabled and disabled properties are optional with enabled being the default. For
 * example:
 * <p>
 * <code>
 * user=password,ROLE_USER
 * admin=secret,ROLE_USER,ROLE_ADMIN
 * disabled_user=does_not_matter,disabled,ROLE_USER
 * </code>
 *
 * @author Rob Winch
 * @since 5.0
 */
public class UserDetailsMapFactoryBean implements FactoryBean<Collection<UserDetails>> {

	private final Map<String, String> userProperties;

	public UserDetailsMapFactoryBean(Map<String, String> userProperties) {
		Assert.notNull(userProperties, "userProperties cannot be null");
		this.userProperties = userProperties;
	}

	@Override
	public Collection<UserDetails> getObject() {
		Collection<UserDetails> users = new ArrayList<>(this.userProperties.size());

		UserAttributeEditor editor = new UserAttributeEditor();
		for (Map.Entry<String, String> entry : this.userProperties.entrySet()) {
			String name = entry.getKey();
			String property = entry.getValue();
			editor.setAsText(property);
			UserAttribute attr = (UserAttribute) editor.getValue();
			if (attr == null) {
				throw new IllegalStateException("The entry with username '" + name + "' and value '" + property
						+ "' could not be converted to a UserDetails.");
			}
			// @formatter:off
			UserDetails user = User.withUsername(name)
				.password(attr.getPassword())
				.disabled(!attr.isEnabled())
				.authorities(attr.getAuthorities())
				.build();
			users.add(user);
			// @formatter:on
		}
		return users;
	}

	@Override
	public Class<?> getObjectType() {
		return Collection.class;
	}

}
