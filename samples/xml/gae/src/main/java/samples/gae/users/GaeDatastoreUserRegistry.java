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

package samples.gae.users;

import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.EntityNotFoundException;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.KeyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import samples.gae.security.AppRole;

import java.util.*;

/**
 * UserRegistry implementation which uses GAE's low-level Datastore APIs.
 *
 * @author Luke Taylor
 */
public class GaeDatastoreUserRegistry implements UserRegistry {
	private final Logger logger = LoggerFactory.getLogger(getClass());

	private static final String USER_TYPE = "GaeUser";
	private static final String USER_FORENAME = "forename";
	private static final String USER_SURNAME = "surname";
	private static final String USER_NICKNAME = "nickname";
	private static final String USER_EMAIL = "email";
	private static final String USER_ENABLED = "enabled";
	private static final String USER_AUTHORITIES = "authorities";

	public GaeUser findUser(String userId) {
		Key key = KeyFactory.createKey(USER_TYPE, userId);
		DatastoreService datastore = DatastoreServiceFactory.getDatastoreService();

		try {
			Entity user = datastore.get(key);

			long binaryAuthorities = (Long) user.getProperty(USER_AUTHORITIES);
			Set<AppRole> roles = EnumSet.noneOf(AppRole.class);

			for (AppRole r : AppRole.values()) {
				if ((binaryAuthorities & (1 << r.getBit())) != 0) {
					roles.add(r);
				}
			}

			GaeUser gaeUser = new GaeUser(user.getKey().getName(),
					(String) user.getProperty(USER_NICKNAME),
					(String) user.getProperty(USER_EMAIL),
					(String) user.getProperty(USER_FORENAME),
					(String) user.getProperty(USER_SURNAME), roles,
					(Boolean) user.getProperty(USER_ENABLED));

			return gaeUser;

		}
		catch (EntityNotFoundException e) {
			logger.debug(userId + " not found in datastore");
			return null;
		}
	}

	public void registerUser(GaeUser newUser) {
		logger.debug("Attempting to create new user " + newUser);

		Key key = KeyFactory.createKey(USER_TYPE, newUser.getUserId());
		Entity user = new Entity(key);
		user.setProperty(USER_EMAIL, newUser.getEmail());
		user.setProperty(USER_NICKNAME, newUser.getNickname());
		user.setProperty(USER_FORENAME, newUser.getForename());
		user.setProperty(USER_SURNAME, newUser.getSurname());
		user.setUnindexedProperty(USER_ENABLED, newUser.isEnabled());

		Collection<AppRole> roles = newUser.getAuthorities();

		long binaryAuthorities = 0;

		for (AppRole r : roles) {
			binaryAuthorities |= 1 << r.getBit();
		}

		user.setUnindexedProperty(USER_AUTHORITIES, binaryAuthorities);

		DatastoreService datastore = DatastoreServiceFactory.getDatastoreService();
		datastore.put(user);
	}

	public void removeUser(String userId) {
		DatastoreService datastore = DatastoreServiceFactory.getDatastoreService();
		Key key = KeyFactory.createKey(USER_TYPE, userId);

		datastore.delete(key);
	}
}
