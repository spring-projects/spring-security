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
package org.springframework.security.abac;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.Expression;
import org.springframework.security.abac.model.Policy;
import org.springframework.security.abac.model.PolicyChecker;
import org.springframework.security.abac.model.PolicyService;

import java.util.List;

/**
 * Default implemenation of ABAC policy checker. It grants access if one (the first) policy served by PolicyService matches
 *
 * @author Renato Soppelsa
 * @since 5.0
 */
public class DefaultPolicyCheckerImpl implements PolicyChecker {

	private static final Log logger = LogFactory.getLog(DefaultPolicyCheckerImpl.class);

	private PolicyService policyService;

	public DefaultPolicyCheckerImpl(PolicyService policyService) {
		this.policyService = policyService;
	}

	@Override
	public boolean check(Object subject, Object resource, Object action, Object environment) {
		List<Policy> policies = policyService.getPolicies(resource != null ? resource.getClass().getSimpleName() : null);
		AbacContext context = new AbacContext(subject, resource, action, environment);
		return checkPolicies(policies, context);
	}

	boolean checkPolicies(List<Policy> policies, AbacContext context) {
		for (Policy policy : policies) {
			if (isPolicyApplicable(policy, context)) {
				boolean contioionSatisfied = isPolicyConditionSatisfied(policy, context);
				if (contioionSatisfied) {
					if (logger.isDebugEnabled()) {
						logger.debug("Permission granted due to policy: " + policy.getName());
					}
					return true;
				}
			}
		}
		return false;
	}

	boolean isPolicyApplicable(Policy policy, AbacContext context) {
		return evaluate(policy.getApplicable(), context, policy.getName());
	}

	boolean isPolicyConditionSatisfied(Policy policy, AbacContext context) {
		return evaluate(policy.getCondition(), context, policy.getName());
	}

	private boolean evaluate(Expression expression, AbacContext context, String policyName) {
		if (expression != null) {
			try {
				if (expression.getValue(context, Boolean.class)) {
					return true;
				}
			} catch (EvaluationException ex) {
				logger.error("Evaluating expression failed. Policy: " + policyName + " ,Expression: " + expression.getExpressionString(), ex);
			}
		}
		return false;
	}
}
