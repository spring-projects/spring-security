/*
 * Copyright 2002-2016 the original author or authors.
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
/**
 *
 */
package sample.service.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import sample.dao.UserDAO;
import sample.domain.User;
import sample.service.UserService;

/**
 * @author A207119
 *
 */
@Component
@Transactional
public class UserServiceImpl implements UserService {

	/** The logger */
	private static final Log LOG = LogFactory.getLog(UserServiceImpl.class);

	/** The User DAO */
	@Autowired
	private UserDAO userDAO = null;

	public UserDetails loadUserByUsername(String username)
			throws AuthenticationException {
		try {
			User user = userDAO.findByUsername(username);

			return new org.springframework.security.core.userdetails.User(user
					.getUsername(), user.getPassword(), true, true, true, true,
					AuthorityUtils.createAuthorityList("ROLE_USER"));
		} catch (Exception e) {
			LOG.error(e.getMessage(), e);
			throw new UsernameNotFoundException("No matching account", e);
		}
	}

	public UserDetails register(String username, String password) {
		User user = new User(username, password);
		userDAO.persist(user);
		return new org.springframework.security.core.userdetails.User(user
				.getUsername(), user.getPassword(), true, true, true, true,
				AuthorityUtils.createAuthorityList("ROLE_USER"));

	}

	/**
	 * @param userDAO
	 *            the userDAO to set
	 */
	public void setUserDAO(UserDAO userDAO) {
		this.userDAO = userDAO;
	}

}
