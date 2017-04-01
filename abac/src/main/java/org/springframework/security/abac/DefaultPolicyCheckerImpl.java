package org.springframework.security.abac;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.Expression;
import org.springframework.security.abac.model.Policy;
import org.springframework.security.abac.model.PolicyChecker;
import org.springframework.security.abac.model.PolicyService;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DefaultPolicyCheckerImpl implements PolicyChecker {

	private static final Log logger = LogFactory.getLog(DefaultPolicyCheckerImpl.class);

	@Autowired
	PolicyService policyService;

	@Override
	public boolean check(Object subject, Object resource, Object action, Object environment) {
		List<Policy> policies = policyService.getPolicies(resource!=null?resource.getClass().getSimpleName():null);
		AbacContext context = new AbacContext(subject, resource, action, environment);
		return checkPolicies(policies, context);
	}

	boolean checkPolicies(List<Policy> policies, AbacContext context) {
		for(Policy policy: policies){
			if(isPolicyApplicable(policy,context)){
				boolean contioionSatisfied = isPolicyConditionSatisfied(policy, context);
				if(contioionSatisfied){
					if (logger.isDebugEnabled()) {
						logger.debug("Permission granted due to policy: " + policy.getName());
					}
					return contioionSatisfied;
				}
			}
		}
		return false;
	}

	boolean isPolicyApplicable(Policy policy, AbacContext context){
		return evaluate(policy.getApplicable(), context, policy.getName());
	}

	boolean isPolicyConditionSatisfied(Policy policy, AbacContext context){
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
