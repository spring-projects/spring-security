/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity.captcha;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import net.sf.acegisecurity.context.HttpSessionContextIntegrationFilter;
import net.sf.acegisecurity.context.SecurityContextHolder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;

/**
 * Filter for web integration of the {@link CaptchaServiceProxy}. <br/> It
 * basically intercept calls containing the specific validation parameter, use
 * the {@link CaptchaServiceProxy} to validate the request, and update the
 * {@link CaptchaSecurityContext} if the request passed the validation. <br/>
 * <br/> This Filter should be placed after the ContextIntegration filter and
 * before the {@link CaptchaChannelProcessor} filter in the filter stack in
 * order to update the {@link CaptchaSecurityContext} before the humanity
 * verification routine occurs. <br/> <br/> This filter should only be used in
 * conjunction with the {@link CaptchaSecurityContext} <br/> <br/>
 * 
 * 
 * @author marc antoine Garrigue
 * @version $Id$
 */
public class CaptchaValidationProcessingFilter implements InitializingBean,
		Filter {
	// ~ Static fields/initializers
	// =============================================
	public static String CAPTCHA_VALIDATION_SECURITY_PARAMETER_KEY = "_captcha_parameter";

	protected static final Log logger = LogFactory
			.getLog(HttpSessionContextIntegrationFilter.class);

	// ~ Instance fields
	// ========================================================

	private CaptchaServiceProxy captchaService;

	// ~ Methods
	// ================================================================

	public CaptchaServiceProxy getCaptchaService() {
		return captchaService;
	}

	public void setCaptchaService(CaptchaServiceProxy captchaService) {
		this.captchaService = captchaService;
	}

	public void afterPropertiesSet() throws Exception {
		if (this.captchaService == null) {
			throw new IllegalArgumentException(
					"CaptchaServiceProxy must be defined ");
		}
	}

	/**
	 * Does nothing. We use IoC container lifecycle services instead.
	 */
	public void destroy() {
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		if ((request != null)
				&& (request
						.getParameter(CAPTCHA_VALIDATION_SECURITY_PARAMETER_KEY) != null)) {
			logger.debug("captcha validation parameter not found, do nothing");
			// validate the request against CaptchaServiceProxy
			boolean valid = false;

			logger.debug("try to validate");
			valid = this.captchaService.validateRequest(request);
			logger.debug("captchaServiceProxy says : request is valid ="
					+ valid);
			if (valid) {
				logger.debug("update the context");
				((CaptchaSecurityContext) SecurityContextHolder.getContext())
						.setHuman();

			}

		} else {
			logger.debug("captcha validation parameter not found, do nothing");
		}
		logger.debug("chain...");
		chain.doFilter(request, response);
	}

	/**
	 * Does nothing. We use IoC container lifecycle services instead.
	 * 
	 * @param filterConfig
	 *            ignored
	 * 
	 * @throws ServletException
	 *             ignored
	 */
	public void init(FilterConfig filterConfig) throws ServletException {
	}
}
