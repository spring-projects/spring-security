/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.webauthn.management;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.util.Assert;

/**
 * A {@link Map} based implementation of {@link PublicKeyCredentialUserEntityRepository}.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class MapPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository {

	private final Map<String, PublicKeyCredentialUserEntity> usernameToUserEntity = new HashMap<>();

	private final Map<Bytes, PublicKeyCredentialUserEntity> idToUserEntity = new HashMap<>();

	@Override
	public PublicKeyCredentialUserEntity findById(Bytes id) {
		Assert.notNull(id, "id cannot be null");
		return this.idToUserEntity.get(id);
	}

	@Override
	public PublicKeyCredentialUserEntity findByUsername(String username) {
		Assert.notNull(username, "username cannot be null");
		return this.usernameToUserEntity.get(username);
	}

	@Override
	public void save(PublicKeyCredentialUserEntity userEntity) {
		if (userEntity == null) {
			throw new IllegalArgumentException("userEntity cannot be null");
		}
		this.usernameToUserEntity.put(userEntity.getName(), userEntity);
		this.idToUserEntity.put(userEntity.getId(), userEntity);
	}

	@Override
	public void delete(Bytes id) {
		PublicKeyCredentialUserEntity existing = this.idToUserEntity.remove(id);
		if (existing != null) {
			this.usernameToUserEntity.remove(existing.getName());
		}
	}

}
