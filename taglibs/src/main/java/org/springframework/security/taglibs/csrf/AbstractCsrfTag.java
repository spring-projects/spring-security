/*
 * Copyright 2002-2014 the original author or authors.
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

package org.springframework.security.taglibs.csrf;

import java.io.IOException;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;

import org.springframework.security.web.csrf.CsrfToken;

/**
 * An abstract tag for handling CSRF operations.
 *
 * @author Nick Williams
 * @since 3.2.2
 */
abstract class AbstractCsrfTag extends TagSupport {

	@Override
	public int doEndTag() throws JspException {

		CsrfToken token = (CsrfToken) this.pageContext.getRequest().getAttribute(CsrfToken.class.getName());
		if (token != null) {
			try {
				this.pageContext.getOut().write(this.handleToken(token));
			}
			catch (IOException e) {
				throw new JspException(e);
			}
		}

		return EVAL_PAGE;
	}

	protected abstract String handleToken(CsrfToken token);

}
