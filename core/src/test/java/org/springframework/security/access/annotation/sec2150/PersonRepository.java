/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.access.annotation.sec2150;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Note that JSR-256 states that annotations have no impact when placed on interfaces, so
 * SEC-2150 is not impacted by JSR-256 support.
 *
 * @author Rob Winch
 *
 */
@Secured("ROLE_PERSON")
@PreAuthorize("hasRole('ROLE_PERSON')")
public interface PersonRepository extends CrudRepository {

}