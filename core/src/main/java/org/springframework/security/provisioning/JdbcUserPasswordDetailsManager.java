/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.provisioning;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;

/**
 * Jdbc user management manager, based on the same table structure as the base class,
 * <tt>JdbcDaoImpl</tt>.
 * <p>
 * This manager will automatically keep the password of the
 * user encoded with the current password encoding, making it easier to manage
 * password security over time.
 * <p>
 * Provides CRUD operations for both users and groups. Note that if the
 * {@link #setEnableAuthorities(boolean) enableAuthorities} property is set to false,
 * calls to createUser, updateUser and deleteUser will not store the authorities from the
 * <tt>UserDetails</tt> or delete authorities for the user. Since this class cannot
 * differentiate between authorities which were loaded for an individual or for a group of
 * which the individual is a member, it's important that you take this into account when
 * using this implementation for managing your users.
 *
 * @author Geir Hedemark
 * @since TBD
 */
public class JdbcUserPasswordDetailsManager extends JdbcUserDetailsManager implements UserDetailsPasswordService {

	@Override
	public UserDetails updatePassword(UserDetails user, String newPassword) {
		this.logger.debug("Updating password for user '" + user.getUsername() + "'");
		getJdbcTemplate().update(this.changePasswordSql, newPassword, user.getUsername());
		this.userCache.removeUserFromCache(user.getUsername());
		return User.withUserDetails(user).password(newPassword).build();
	}
}
