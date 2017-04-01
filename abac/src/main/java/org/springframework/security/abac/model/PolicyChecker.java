package org.springframework.security.abac.model;

public interface PolicyChecker {
	boolean check(Object subject, Object resource, Object action, Object environment);
}
