/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.web.authentication.supply;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.www.AuthenticationType;

/**
 * @author Sergey Bespalov
 *
 */
public class AuthenticationSupplierMap implements AuthenticationSupplierRegistry {

	private Map<AuthenticationType, AuthenticationSupplier<?>> authenticationSupplierMap = new ConcurrentHashMap<>();

	public AuthenticationSupplierMap(Set<AuthenticationSupplier<?>> authenticationSuppliers) {
		super();
		authenticationSuppliers.stream().forEach(s -> authenticationSupplierMap.put(s.getAuthenticationType(), s));
	}

	@Override
	public <T extends Authentication> AuthenticationSupplier<T> lookupSupplierByAuthenticationType(
			AuthenticationType authenticationType) {
		return (AuthenticationSupplier<T>) authenticationSupplierMap.get(authenticationType);
	}

}
