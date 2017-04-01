package org.springframework.security.abac.json;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.expression.Expression;
import org.springframework.security.abac.model.Policy;
import org.springframework.security.abac.model.PolicyService;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
/**
 * Default implementation to load ABAC policies from jason file located in resource folder.
 */
public class JsonFilePolicyServiceImpl implements PolicyService {

	private static final Log logger = LogFactory.getLog(JsonFilePolicyServiceImpl.class);

	private static String DEFAULT_POLICY_FILENAME = "policy.abac.json";

	@Value("${policy.json.filePath}")
	private String policyFilePath;

	private LinkedMultiValueMap<String, Policy> policies;

	@PostConstruct
	private void init(){
		ObjectMapper mapper = new ObjectMapper();
		SimpleModule module = new SimpleModule();
		module.addDeserializer(Expression.class, new SpElDeserializer());
		mapper.registerModule(module);
		Policy[] rulesArray = null;
			Resource resource = new ClassPathResource(policyFilePath);
			if(resource.exists()) {
				rulesArray = loadPolicyFile(resource, mapper);
			} else {
				Resource defaultPolicyResource = new ClassPathResource(DEFAULT_POLICY_FILENAME);
				if(defaultPolicyResource.exists()){
					rulesArray = loadPolicyFile(defaultPolicyResource, mapper);
				}
			}
			if(rulesArray!=null) {
				policies = mapPolicyArrayToMap(rulesArray);
				logger.info("Policies loaded successfully.");
			}
			else {
				logger.warn("No policies were loaded.");
			}
	}

	Policy[] loadPolicyFile(Resource resource, ObjectMapper mapper){
		Policy[] rulesArray = null;
		try {
			logger.info("Loading policies from file: " + resource.getFilename());
			rulesArray = mapper.readValue(resource.getFile(), Policy[].class);
		} catch (JsonMappingException e) {
			logger.error("Mapping of policy file failed: " + resource.getFilename(), e);
		} catch (IOException e) {
			logger.error("Reading the policy file failed: " + resource.getFilename(), e);
		}
		return rulesArray;
	}


	LinkedMultiValueMap<String, Policy> mapPolicyArrayToMap(Policy[] policies){
		LinkedMultiValueMap<String, Policy> map = new LinkedMultiValueMap<String, Policy>();
		if(policies!=null || policies.length>0){
			for(Policy policy: policies){
				String key = policy.getType();
				if(key == null || key.trim().length()==0){
					map.add("", policy);
				}
				else {
					map.add(key.trim(), policy);
				}
			}
		}
		return map;
	}

	@Override
	public List<Policy> getAllPolicies() {
		List<Policy> allPolicies = new ArrayList<Policy>();
		if(policies!=null){
			for(String key: policies.keySet()){
				allPolicies.addAll(policies.get(key));
			}
		}
		return allPolicies;
	}

	@Override
	public List<Policy> getPolicies(String type) {
		List<Policy> allPolicies = new ArrayList<Policy>();
		if(policies!=null){
			//add all general policies with no specific class
			if(policies.containsKey("")){
				allPolicies.addAll(policies.get(""));
			}
			//add specific policies for a class
			if(type !=null && type.trim().length()>0 && policies.containsKey(type.trim())){
				allPolicies.addAll(policies.get(type.trim()));
			}
		}
		return allPolicies;
	}
}
