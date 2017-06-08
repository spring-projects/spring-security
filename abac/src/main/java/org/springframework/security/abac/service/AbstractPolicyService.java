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
package org.springframework.security.abac.service;

import org.springframework.security.abac.model.Policy;
import org.springframework.security.abac.model.PolicyService;
import org.springframework.util.LinkedMultiValueMap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * @author Renato Soppelsa
 * @since 5.0.0
 */
public abstract class AbstractPolicyService implements PolicyService {

	private LinkedMultiValueMap<String, Policy> policyMap;

	public abstract void reloadPolicies();

	/**
	 * Gets all policies defined in the json file
	 *
	 * @return list of all available Policies
	 */
	@Override
	public List<Policy> getAllPolicies() {
		List<Policy> allPolicies = new ArrayList<Policy>();
		if (policyMap != null) {
			for (String key : policyMap.keySet()) {
				allPolicies.addAll(policyMap.get(key));
			}
		}
		return allPolicies;
	}

	/**
	 * @param type used to filter policies, usual the class simple name. i.e BlogEntry
	 * @return filtered list of Policies to check
	 */
	@Override
	public List<Policy> getPolicies(String type) {
		List<Policy> allPolicies = new ArrayList<Policy>();
		if (policyMap != null) {
			//add all general policies with no specific class
			if (policyMap.containsKey("")) {
				allPolicies.addAll(policyMap.get(""));
			}
			//add specific policies for a class
			if (type != null && type.trim().length() > 0 && policyMap.containsKey(type.trim())) {
				allPolicies.addAll(policyMap.get(type.trim()));
			}
		}
		return allPolicies;
	}

	public void setPolicies(Collection<Policy> policies) {
		this.policyMap = mapPolicyArrayToMap(policies);
	}

	public LinkedMultiValueMap<String, Policy> getPolicies() {
		return policyMap;
	}

	private LinkedMultiValueMap<String, Policy> mapPolicyArrayToMap(Collection<Policy> policies) {
		LinkedMultiValueMap<String, Policy> map = new LinkedMultiValueMap<String, Policy>();
		if (policies != null) {
			Iterator<Policy> iterator = policies.iterator();
			while (iterator.hasNext()) {
				Policy policy = iterator.next();
				String key = policy.getType();
				if (key == null || key.trim().length() == 0) {
					map.add("", policy);
				} else {
					map.add(key.trim(), policy);
				}
			}
		}
		return map;
	}
}
