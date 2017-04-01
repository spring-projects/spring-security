package org.springframework.security.abac.model;

import java.util.List;

public interface PolicyService {

	List<Policy> getAllPolicies();

	List<Policy> getPolicies(String type);
}
