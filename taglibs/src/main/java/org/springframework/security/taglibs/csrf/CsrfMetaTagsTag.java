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

import org.springframework.security.web.csrf.CsrfToken;

/**
 * A JSP tag that prints out a meta tags holding the CSRF form field name and token value
 * for use in JavaScrip code. See the JSP Tab Library documentation for more information.
 *
 * @author Nick Williams
 * @since 3.2.2
 */
public class CsrfMetaTagsTag extends AbstractCsrfTag {

	@Override
	public String handleToken(CsrfToken token) {
		return "<meta name=\"_csrf_parameter\" content=\"" + token.getParameterName() + "\" />"
				+ "<meta name=\"_csrf_header\" content=\"" + token.getHeaderName() + "\" />"
				+ "<meta name=\"_csrf\" content=\"" + token.getToken() + "\" />";
	}

}
