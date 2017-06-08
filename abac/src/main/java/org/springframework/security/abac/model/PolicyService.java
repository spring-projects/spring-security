/*
 * Copyright 2017-2017 the original author or authors.
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
package org.springframework.security.abac.model;

import java.util.List;

/**
 * Interface to return policies
 *
 * @author Renato Soppelsa
 * @since 5.0
 */
public interface PolicyService {

	/**
	 *
	 * @return all available policies
	 */
	List<Policy> getAllPolicies();

	/**
	 * @param type as String with matches the type specified in the policiy definition. Used to filter the result list.
	 * @return filterd policy list based on the "type"
	 */
	List<Policy> getPolicies(String type);
}
