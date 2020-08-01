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

package org.springframework.security.taglibs.authz;

import java.io.IOException;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.tagext.Tag;
import javax.servlet.jsp.tagext.TagSupport;

import org.springframework.beans.BeanWrapperImpl;
import org.springframework.beans.BeansException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.TextEscapeUtils;
import org.springframework.web.util.TagUtils;

/**
 * An {@link javax.servlet.jsp.tagext.Tag} implementation that allows convenient access to
 * the current <code>Authentication</code> object.
 * <p>
 * Whilst JSPs can access the <code>SecurityContext</code> directly, this tag avoids
 * handling <code>null</code> conditions.
 *
 * @author Thomas Champagne
 */
public class AuthenticationTag extends TagSupport {

	private String var;

	private String property;

	private int scope;

	private boolean scopeSpecified;

	private boolean htmlEscape = true;

	public AuthenticationTag() {
		init();
	}

	// resets local state
	private void init() {
		this.var = null;
		this.scopeSpecified = false;
		this.scope = PageContext.PAGE_SCOPE;
	}

	public void setVar(String var) {
		this.var = var;
	}

	public void setProperty(String operation) {
		this.property = operation;
	}

	public void setScope(String scope) {
		this.scope = TagUtils.getScope(scope);
		this.scopeSpecified = true;
	}

	@Override
	public int doStartTag() throws JspException {
		return super.doStartTag();
	}

	@Override
	public int doEndTag() throws JspException {
		Object result = null;
		// determine the value by...
		if (this.property != null) {
			if ((SecurityContextHolder.getContext() == null)
					|| !(SecurityContextHolder.getContext() instanceof SecurityContext)
					|| (SecurityContextHolder.getContext().getAuthentication() == null)) {
				return Tag.EVAL_PAGE;
			}
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			if (auth.getPrincipal() == null) {
				return Tag.EVAL_PAGE;
			}
			try {
				BeanWrapperImpl wrapper = new BeanWrapperImpl(auth);
				result = wrapper.getPropertyValue(this.property);
			}
			catch (BeansException ex) {
				throw new JspException(ex);
			}
		}
		if (this.var != null) {
			/*
			 * Store the result, letting an IllegalArgumentException propagate back if the
			 * scope is invalid (e.g., if an attempt is made to store something in the
			 * session without any HttpSession existing).
			 */
			if (result != null) {
				this.pageContext.setAttribute(this.var, result, this.scope);
			}
			else {
				if (this.scopeSpecified) {
					this.pageContext.removeAttribute(this.var, this.scope);
				}
				else {
					this.pageContext.removeAttribute(this.var);
				}
			}
		}
		else {
			if (this.htmlEscape) {
				writeMessage(TextEscapeUtils.escapeEntities(String.valueOf(result)));
			}
			else {
				writeMessage(String.valueOf(result));
			}
		}
		return EVAL_PAGE;
	}

	protected void writeMessage(String msg) throws JspException {
		try {
			this.pageContext.getOut().write(String.valueOf(msg));
		}
		catch (IOException ioe) {
			throw new JspException(ioe);
		}
	}

	/**
	 * Set HTML escaping for this tag, as boolean value.
	 */
	public void setHtmlEscape(String htmlEscape) {
		this.htmlEscape = Boolean.parseBoolean(htmlEscape);
	}

	/**
	 * Return the HTML escaping setting for this tag, or the default setting if not
	 * overridden.
	 */
	protected boolean isHtmlEscape() {
		return this.htmlEscape;
	}

}
