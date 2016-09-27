/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.taglibs.redirect;

import javax.servlet.ServletRequest;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;

import org.springframework.security.web.redirect.SignCalculator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A JSP tag to generate hidden field for signature of redirect target URL.
 *
 * @author Takuya Iwatsuka
 */
@SuppressWarnings("serial")
public class RedirectorTag extends TagSupport {

	private String redirectorUrl;

	private String text;

	private String targetUrl;

	private boolean hidden = false;

	public void setRedirectorUrl(String redirectorUrl) {
		this.redirectorUrl = redirectorUrl;
	}

	public String getRedirectorUrl() {
		return redirectorUrl;
	}

	public void setText(String text) {
		this.text = text;
	}

	public String getText() {
		return text;
	}

	public void setTargetUrl(String targetUrl) {
		Assert.hasLength(targetUrl);
		this.targetUrl = targetUrl;
	}

	public String getTargetUrl() {
		return targetUrl;
	}

	public void setHidden(boolean hidden) {
		this.hidden = hidden;
	}

	public boolean isHidden() {
		return hidden;
	}

	@Override
	public int doEndTag() throws JspException {
		if(!hidden && !StringUtils.hasLength(redirectorUrl)){
			throw new JspException("The value of redirectorUrl must not be empty.");
		}

		ServletRequest request = pageContext.getRequest();
		SignCalculator signCalculator = (SignCalculator) request
				.getAttribute("_signCalculator");
		String redirectParameter = (String) request
				.getAttribute("_redirectParameter");
		String signParameter = (String) request.getAttribute("_signParameter");
		String sign = signCalculator.calculateSign(targetUrl);

		StringBuilder builder;
		if(hidden){
			builder = new StringBuilder(
					"<input type=\"hidden\" name=\"").append(redirectParameter)
					.append("\" value=\"").append(targetUrl).append("\" />\n")
					.append("<input type=\"hidden\" name=\"").append(signParameter)
					.append("\" value=\"")
					.append(sign)
					.append("\" />");
		} else {
			UriComponents uriComponent = UriComponentsBuilder.fromUriString(redirectorUrl)
					.queryParam(redirectParameter, targetUrl)
					.queryParam(signParameter, sign).build();
			builder = new StringBuilder("<a href=\"")
					.append(uriComponent.toUriString())
					.append("\">");
			if(StringUtils.hasLength(text)){
				builder.append(text);
			}else{
				builder.append(redirectorUrl);
			}
			builder.append("</a>");
		}

		try {
			pageContext.getOut().write(builder.toString());
		} catch (Exception e) {
			throw new JspException(e);
		}

		return EVAL_PAGE;
	}
}
