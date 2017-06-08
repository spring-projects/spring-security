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
package org.springframework.security.abac.service.json;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.expression.Expression;
import org.springframework.security.abac.PolicyImpl;
import org.springframework.security.abac.model.Policy;
import org.springframework.security.abac.model.PolicyService;
import org.springframework.security.abac.service.AbstractPolicyService;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Default implementation to load ABAC policies from json file located in resource folder.
 *
 * @author Renato Soppelsa
 * @since 5.0
 */
public class JsonFilePolicyServiceImpl extends AbstractPolicyService {

	private static final Log logger = LogFactory.getLog(JsonFilePolicyServiceImpl.class);

	private static String DEFAULT_POLICY_FILENAME = "policy.abac.json";

	private String policyFilePath;

	public JsonFilePolicyServiceImpl(String policyFilePath) {
		this.policyFilePath = policyFilePath;
		loadPolicies();
	}

	private void loadPolicies() {
		ObjectMapper mapper = new ObjectMapper();
		SimpleModule module = new SimpleModule();
		module.addDeserializer(Expression.class, new SpElDeserializer());
		mapper.registerModule(module);
		Policy[] policies = null;
		Resource resource = null;
		if (!StringUtils.isEmpty(policyFilePath)) {
			resource = new ClassPathResource(policyFilePath);
		}
		else {
			policyFilePath = DEFAULT_POLICY_FILENAME;
			resource = new ClassPathResource(policyFilePath);
		}
		if (resource != null && resource.exists()) {
			policies = loadPolicyFile(resource, mapper);
		}
		else {
			logger.info("ABAC policy file not found: " + policyFilePath);
		}
		if (policies != null) {
			setPolicies(Arrays.asList(policies));
			logger.info("ABAC policies loaded successfully.");
		} else {
			logger.warn("No ABAC policies were loaded.");
		}
	}

	Policy[] loadPolicyFile(Resource resource, ObjectMapper mapper) {
		Policy[] rulesArray = null;
		try {
			logger.info("Loading policies from file: " + resource.getFilename());
			rulesArray = mapper.readValue(resource.getFile(), PolicyImpl[].class);
		} catch (JsonMappingException e) {
			logger.error("Mapping of policy file failed: " + resource.getFilename(), e);
		} catch (IOException e) {
			logger.error("Reading the policy file failed: " + resource.getFilename(), e);
		}
		return rulesArray;
	}

	@Override
	public void reloadPolicies() {
		loadPolicies();
	}
}
