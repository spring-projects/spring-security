/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.taglibs.authz;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.tagext.Tag;

import org.springframework.expression.BeanResolver;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.OperatorOverloader;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypeComparator;
import org.springframework.expression.TypeConverter;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.TypedValue;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.taglibs.TagLibConfig;
import org.springframework.security.web.FilterInvocation;

/**
 * A JSP {@link Tag} implementation of {@link AbstractAuthorizeTag}.
 *
 * @author Rossen Stoyanchev
 * @since 3.1.0
 * @see AbstractAuthorizeTag
 */
public class JspAuthorizeTag extends AbstractAuthorizeTag implements Tag {

	private Tag parent;

	protected PageContext pageContext;

	protected String id;

	private String var;

	private boolean authorized;

	/**
	 * Invokes the base class {@link AbstractAuthorizeTag#authorize()} method to decide if
	 * the body of the tag should be skipped or not.
	 * @return {@link Tag#SKIP_BODY} or {@link Tag#EVAL_BODY_INCLUDE}
	 */
	@Override
	public int doStartTag() throws JspException {
		try {
			this.authorized = super.authorize();
			if (!this.authorized && TagLibConfig.isUiSecurityDisabled()) {
				this.pageContext.getOut().write(TagLibConfig.getSecuredUiPrefix());
			}
			if (this.var != null) {
				this.pageContext.setAttribute(this.var, this.authorized, PageContext.PAGE_SCOPE);
			}
			return TagLibConfig.evalOrSkip(this.authorized);
		}
		catch (IOException ex) {
			throw new JspException(ex);
		}
	}

	@Override
	protected EvaluationContext createExpressionEvaluationContext(SecurityExpressionHandler<FilterInvocation> handler) {
		return new PageContextVariableLookupEvaluationContext(super.createExpressionEvaluationContext(handler));
	}

	/**
	 * Default processing of the end tag returning EVAL_PAGE.
	 * @return EVAL_PAGE
	 * @see Tag#doEndTag()
	 */
	@Override
	public int doEndTag() throws JspException {
		try {
			if (!this.authorized && TagLibConfig.isUiSecurityDisabled()) {
				this.pageContext.getOut().write(TagLibConfig.getSecuredUiSuffix());
			}
		}
		catch (IOException ex) {
			throw new JspException(ex);
		}
		return EVAL_PAGE;
	}

	public String getId() {
		return this.id;
	}

	public void setId(String id) {
		this.id = id;
	}

	@Override
	public Tag getParent() {
		return this.parent;
	}

	@Override
	public void setParent(Tag parent) {
		this.parent = parent;
	}

	public String getVar() {
		return this.var;
	}

	public void setVar(String var) {
		this.var = var;
	}

	@Override
	public void release() {
		this.parent = null;
		this.id = null;
	}

	@Override
	public void setPageContext(PageContext pageContext) {
		this.pageContext = pageContext;
	}

	@Override
	protected ServletRequest getRequest() {
		return this.pageContext.getRequest();
	}

	@Override
	protected ServletResponse getResponse() {
		return this.pageContext.getResponse();
	}

	@Override
	protected ServletContext getServletContext() {
		return this.pageContext.getServletContext();
	}

	private final class PageContextVariableLookupEvaluationContext implements EvaluationContext {

		private EvaluationContext delegate;

		private PageContextVariableLookupEvaluationContext(EvaluationContext delegate) {
			this.delegate = delegate;
		}

		@Override
		public TypedValue getRootObject() {
			return this.delegate.getRootObject();
		}

		@Override
		public List<ConstructorResolver> getConstructorResolvers() {
			return this.delegate.getConstructorResolvers();
		}

		@Override
		public List<MethodResolver> getMethodResolvers() {
			return this.delegate.getMethodResolvers();
		}

		@Override
		public List<PropertyAccessor> getPropertyAccessors() {
			return this.delegate.getPropertyAccessors();
		}

		@Override
		public TypeLocator getTypeLocator() {
			return this.delegate.getTypeLocator();
		}

		@Override
		public TypeConverter getTypeConverter() {
			return this.delegate.getTypeConverter();
		}

		@Override
		public TypeComparator getTypeComparator() {
			return this.delegate.getTypeComparator();
		}

		@Override
		public OperatorOverloader getOperatorOverloader() {
			return this.delegate.getOperatorOverloader();
		}

		@Override
		public BeanResolver getBeanResolver() {
			return this.delegate.getBeanResolver();
		}

		@Override
		public void setVariable(String name, Object value) {
			this.delegate.setVariable(name, value);
		}

		@Override
		public Object lookupVariable(String name) {
			Object result = this.delegate.lookupVariable(name);
			if (result == null) {
				result = JspAuthorizeTag.this.pageContext.findAttribute(name);
			}
			return result;
		}

	}

}
