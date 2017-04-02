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

import org.springframework.expression.Expression;
import org.springframework.security.abac.model.Policy;

/**
 * Plain java bean to hold the policy definition
 *
 * @author Renato Soppelsa
 * @since 5.0
 */
public class PolicyImpl implements Policy {

	private String name;
	private String description;
	private String type;
	private Expression applicable;
	private Expression condition;

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public String getType() {
		return type;
	}

	@Override
	public Expression getApplicable() {
		return applicable;
	}

	@Override
	public Expression getCondition() {
		return condition;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public void setType(String type) {
		this.type = type;
	}

	public void setApplicable(Expression applicable) {
		this.applicable = applicable;
	}

	public void setCondition(Expression condition) {
		this.condition = condition;
	}

	@Override
	public String toString() {
		return "PolicyImpl{" +
			"name='" + name + '\'' +
			", description='" + description + '\'' +
			", type='" + type + '\'' +
			", applicable=" + applicable.getExpressionString() +
			", condition=" + condition.getExpressionString() +
			'}';
	}
}
