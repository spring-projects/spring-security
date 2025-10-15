/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.docs.servlet.servletdelegatingfilterproxy;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import org.springframework.web.context.support.StaticWebApplicationContext;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

/**
 * A very simple implementation of a DelegatingFilterProxy.
 */
public class SampleDelegatingFilterProxy extends GenericFilterBean {

	private StaticWebApplicationContext wac;
	private final String someBeanName;

	public SampleDelegatingFilterProxy(String someBeanName, StaticWebApplicationContext webApplicationContext) {
		this.wac = webApplicationContext;
		this.someBeanName = someBeanName;
	}

	// tag::dofilter[]
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		Filter delegate = getFilterBean(someBeanName); // <1>
		delegate.doFilter(request, response, chain); // <2>
	}
	// end::dofilter[]

	private Filter getFilterBean(String someBeanName) {
		return this.wac.getBean(someBeanName, Filter.class);
	}
}
