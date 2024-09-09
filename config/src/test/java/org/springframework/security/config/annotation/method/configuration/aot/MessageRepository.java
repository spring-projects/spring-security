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

package org.springframework.security.config.annotation.method.configuration.aot;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.stereotype.Repository;

/**
 * A repository for accessing {@link Message}s.
 *
 * @author Rob Winch
 */
@Repository
@AuthorizeReturnObject
public interface MessageRepository extends CrudRepository<Message, Long> {

	@Query("select m from Message m where m.to.id = ?#{ authentication.name }")
	Iterable<Message> findAll();

	@Query("from org.springframework.security.config.annotation.method.configuration.aot.User u where u.id = ?#{ authentication.name }")
	UserProjection findCurrentUser();

}
