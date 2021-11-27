/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletContext;

/**
 * @author Ben Alex
 */
@SuppressWarnings("unchecked")
public class MockFilterConfig implements FilterConfig {

	private Map map = new HashMap();

	@Override
	public String getFilterName() {
		throw new UnsupportedOperationException("mock method not implemented");
	}

	@Override
	public String getInitParameter(String arg0) {
		Object result = this.map.get(arg0);
		if (result != null) {
			return (String) result;
		}
		else {
			return null;
		}
	}

	@Override
	public Enumeration getInitParameterNames() {
		throw new UnsupportedOperationException("mock method not implemented");
	}

	@Override
	public ServletContext getServletContext() {
		throw new UnsupportedOperationException("mock method not implemented");
	}

	public void setInitParmeter(String parameter, String value) {
		this.map.put(parameter, value);
	}

}
