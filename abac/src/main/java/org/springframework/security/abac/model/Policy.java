package org.springframework.security.abac.model;

import org.springframework.expression.Expression;

/**
 * Defines the policy format. Based on that the permission to access is granted
 */
public interface Policy {

	String getName();
	String getDescription();
	String getType();
	Expression getApplicable();
	Expression  getCondition();

}
