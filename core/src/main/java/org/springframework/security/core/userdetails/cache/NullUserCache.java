/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core.userdetails.cache;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Does not perform any caching.
 *
 * @author Ben Alex
 */
public class NullUserCache implements UserCache {

	@Override
	public @Nullable UserDetails getUserFromCache(String username) {
		return null;
	}

	@Override
	public void putUserInCache(UserDetails user) {
	}

	@Override
	public void removeUserFromCache(String username) {
	}

}
