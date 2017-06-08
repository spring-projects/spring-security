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
package org.springframework.security.abac.service.jdbc;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.abac.PolicyImpl;
import org.springframework.security.abac.model.Policy;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * @author Renato Soppelsa
 * @since 5.0.0
 */
public class PolicyRowMapper implements RowMapper<Policy> {

	private SpelExpressionParser spelExpressionParser;

	public PolicyRowMapper() {
		this.spelExpressionParser = new SpelExpressionParser();
	}

	@Override
	public Policy mapRow(ResultSet rs, int rowNum) throws SQLException {
		PolicyImpl policy = new PolicyImpl();
		policy.setId(rs.getLong("id"));
		policy.setName(rs.getString("name"));
		policy.setDescription(rs.getString("description"));
		policy.setType(rs.getString("type"));
		policy.setApplicable(extractExpression(rs, "applicable"));
		policy.setCondition(extractExpression(rs, "condition"));
		return policy;
	}

	private Expression extractExpression(ResultSet rs, String columnName) throws SQLException{
		String expressionString = rs.getString(columnName);
		if(!StringUtils.isEmpty(expressionString)){
			return spelExpressionParser.parseExpression(expressionString);
		}
		return null;
	}
}
