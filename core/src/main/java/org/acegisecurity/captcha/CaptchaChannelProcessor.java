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
import java.util.Iterator;

import javax.servlet.ServletException;

import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.context.SecurityContextHolder;
import net.sf.acegisecurity.intercept.web.FilterInvocation;
import net.sf.acegisecurity.securechannel.ChannelEntryPoint;
import net.sf.acegisecurity.securechannel.ChannelProcessor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * <p>
 * Ensures the user has enougth human privileges by review of the
 * {@link net.sf.acegisecurity.captcha.CaptchaSecurityContext}.
 * </p>
 * 
 * <P>
 * The class takes 3 required attributes :
 * <ul>
 * <li>maxRequestsBeforeFirstTest : used by
 * {@link #getRequiresHumanAfterMaxRequestsKeyword()} and
 * {@link #getRequiresHumanAfterMaxMillisKeyword()}<br>
 * default value = 0 (ie first request).</li>
 * <li>maxRequestsBeforeReTest : used by
 * {@link #getRequiresHumanAfterMaxMillisKeyword()}<br>
 * default value = -1 (ie disabled, once in a {@link CaptchaSecurityContext}'s
 * life).</li>
 * <li>maxMillisBeforeReTest: used by
 * {@link #getRequiresHumanAfterMaxMillisKeyword()} <br>
 * default value = -1 (ie disabled, once in a {@link CaptchaSecurityContext}'s
 * life).</li>
 * </ul>
 * The class responds to two case-sensitive keywords :
 * <ul>
 * <li>{@link #getRequiresHumanAfterMaxRequestsKeyword()} <br>
 * default value = <code>REQUIRES_HUMAN_AFTER_MAX_REQUESTS</code> <br>
 * if detected, checks if :
 * <ul>
 * <ul>
 * <li><code>{@link CaptchaSecurityContext#isHuman()} == true</code> </li>
 * <li><b>or</b></li>
 * <li><code>{@link CaptchaSecurityContext#getHumanRestrictedResourcesRequestsCount()} < maxRequestsBeforeFirstTest</code></b></li>
 * </ul>
 * <li><b>and</b></li>
 * <ul>
 * <li><code>{@link CaptchaSecurityContext#getHumanRestrictedResourcesRequestsCount()} < maxRequestsBeforeReTest </code></li>
 * <li><b>or</b></li>
 * <li><code>maxRequestsBeforeReTest < 0 </code></b></li>
 * </ul>
 * </ul>
 * </li>
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * <li>{@link #getRequiresHumanUntilMaxRequestsKeyword()} <br>
 * default value = <code>REQUIRES_HUMAN_AFTER_MAX_MILLIS</code> <br>
 * if detected, checks if :
 * 
 * <ul>
 * <ul>
 * <li><code>{@link CaptchaSecurityContext#isHuman()} == true</code> </li>
 * <li><b>or</b></li>
 * <li><code>{@link CaptchaSecurityContext#getHumanRestrictedResourcesRequestsCount()} < =maxRequestsBeforeFirstTest</code></b></li>
 * </ul>
 * <li><b>and</b></li>
 * <ul>
 * <li><code>System.currentTimeMillis()-{@link CaptchaSecurityContext#getLastPassedCaptchaDateInMillis()} <= maxMillisBeforeReTest </code></li>
 * <li><b>or</b></li>
 * <li><code>maxMillisBeforeReTest < 0 </code></b></li>
 * </ul>
 * </ul>
 * </li>
 * </ul>
 * </p>
 * 
 * <p>
 * <u>Examples : to ensure an url is accessed only by human that pass a captcha
 * (assuming you are using the
 * {@link net.sf.acegisecurity.context.HttpSessionContextIntegrationFilter})
 * </u><br>
 * <ul>
 * <li>Once in a session and at first request : use the <br>
 * REQUIRES_HUMAN_AFTER_MAX_REQUESTS keyword <br>
 * with a maxRequestsBeforeFirstTest=0<br>
 * and a maxRequestsBeforeReTest=-1<br>
 * </li>
 * <br>
 * &nbsp;
 * <li>Once in a session and only after 3 requests : use the <br>
 * REQUIRES_HUMAN_AFTER_MAX_REQUESTS keyword <br>
 * with a maxRequestsBeforeFirstTest=3</li>
 * and a maxRequestsBeforeReTest=-1<br>
 * <br>
 * &nbsp;
 * <li>Every request and only after 5 requests : use the <br>
 * REQUIRES_HUMAN_AFTER_MAX_REQUESTS <br>
 * with a maxRequestsBeforeReTest=0<br>
 * and a maxRequestsBeforeFirstTest=5</li>
 * <br>
 * &nbsp;
 * <li>Every 3 requests and every minute : use the <br>
 * REQUIRES_HUMAN_AFTER_MAX_MILLIS keywords <br>
 * with a maxMillisBeforeReTest=6000 <br>
 * and a maxRequestsBeforeFirstTest=3</li>
 * <br>
 * &nbsp;
 * <li>Every 20 requests and every hour and only after 100 requests : use the
 * <br>
 * REQUIRES_HUMAN_AFTER_MAX_REQUESTS <br>
 * and the REQUIRES_HUMAN_AFTER_MAX_MILLIS <br>
 * and the REQUIRES_HUMAN_AFTER_MAX_REQUESTS keywords <br>
 * with a maxRequestsBeforeReTest=20 <br>
 * and a maxMillisBeforeReTest=3600000 <br>
 * and amaxRequestsBeforeFirstTest=1000</li>
 * 
 * </ul>
 * 
 * 
 * @author marc antoine Garrigue
 * @version $Id$
 */
public class CaptchaChannelProcessor implements ChannelProcessor,
		InitializingBean {
	// ~ Static fields/initializers
	// =============================================

	private static final Log logger = LogFactory
			.getLog(CaptchaChannelProcessor.class);

	private String requiresHumanAfterMaxRequestsKeyword = "REQUIRES_HUMAN_AFTER_MAX_REQUESTS";

	private String requiresHumanAfterMaxMillisKeyword = "REQUIRES_HUMAN_AFTER_MAX_MILLIS";

	private ChannelEntryPoint entryPoint;

	private int maxRequestsBeforeReTest = -1;

	private int maxRequestsBeforeFirstTest = 0;

	private long maxMillisBeforeReTest = -1;

	public String getRequiresHumanAfterMaxMillisKeyword() {
		return requiresHumanAfterMaxMillisKeyword;
	}

	public void setRequiresHumanAfterMaxMillisKeyword(
			String requiresHumanAfterMaxMillis) {
		this.requiresHumanAfterMaxMillisKeyword = requiresHumanAfterMaxMillis;

	}

	public void setRequiresHumanAfterMaxRequestsKeyword(
			String requiresHumanAfterMaxRequestsKeyword) {
		this.requiresHumanAfterMaxRequestsKeyword = requiresHumanAfterMaxRequestsKeyword;
	}

	public ChannelEntryPoint getEntryPoint() {
		return entryPoint;
	}

	public void setEntryPoint(ChannelEntryPoint entryPoint) {
		this.entryPoint = entryPoint;
	}

	public int getMaxRequestsBeforeReTest() {
		return maxRequestsBeforeReTest;
	}

	public void setMaxRequestsBeforeReTest(int maxRequestsBeforeReTest) {
		this.maxRequestsBeforeReTest = maxRequestsBeforeReTest;
	}

	public String getRequiresHumanAfterMaxRequestsKeyword() {
		return requiresHumanAfterMaxRequestsKeyword;
	}

	public int getMaxRequestsBeforeFirstTest() {
		return maxRequestsBeforeFirstTest;
	}

	public void setMaxRequestsBeforeFirstTest(int maxRequestsBeforeFirstTest) {
		this.maxRequestsBeforeFirstTest = maxRequestsBeforeFirstTest;
	}

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(entryPoint, "entryPoint required");
	}

	public long getMaxMillisBeforeReTest() {
		return maxMillisBeforeReTest;
	}

	public void setMaxMillisBeforeReTest(long maxMillisBeforeReTest) {
		this.maxMillisBeforeReTest = maxMillisBeforeReTest;
	}

	public void decide(FilterInvocation invocation,
			ConfigAttributeDefinition config) throws IOException,
			ServletException {
		if ((invocation == null) || (config == null)) {
			throw new IllegalArgumentException("Nulls cannot be provided");
		}
		CaptchaSecurityContext context = (CaptchaSecurityContext) SecurityContextHolder
				.getContext();

		Iterator iter = config.getConfigAttributes();
		boolean shouldRedirect = true;

		while (iter.hasNext()) {
			ConfigAttribute attribute = (ConfigAttribute) iter.next();

			if (supports(attribute)) {
				logger.debug("supports this attribute : " + attribute);
				if (isContextValidForAttribute(context, attribute)) {
					shouldRedirect = false;
				} else {
					// reset if already passed a constraint

					shouldRedirect = true;
					// break at first unsatisfy contraint
					break;
				}

			}
		}
		if (shouldRedirect) {
			logger
					.debug("context is not allowed to access ressource, redirect to captcha entry point");
			redirectToEntryPoint(invocation);
		} else {
			// if we reach this point, we forward the request so
			// increment it
			logger
					.debug("context is allowed to access ressource, increment rectricted ressource requests count ");
			context.incrementHumanRestrictedRessoucesRequestsCount();

		}
	}

	private boolean isContextValidForAttribute(CaptchaSecurityContext context,
			ConfigAttribute attribute) {
		boolean valid = false;
		if ((attribute != null) || (attribute.getAttribute() != null)) {

			// test the REQUIRES_HUMAN_AFTER_MAX_REQUESTS keyword
			if (attribute.getAttribute().equals(
					getRequiresHumanAfterMaxRequestsKeyword())) {
				if (isContextValidConcerningHumanOrFirstTest(context)
						&& isContextValidConcerningReTest(context)) {
					valid = true;
				}
			}

			// test the REQUIRES_HUMAN_AFTER_MAX_MILLIS keyword
			if (attribute.getAttribute().equals(
					getRequiresHumanAfterMaxMillisKeyword())) {
				if (isContextValidConcerningHumanOrFirstTest(context)
						&& isContextValidConcerningMaxMillis(context)) {
					valid = true;
				}
			}

		}
		return valid;
	}

	private boolean isContextValidConcerningHumanOrFirstTest(
			CaptchaSecurityContext context) {
		if (context.isHuman()
				|| context.getHumanRestrictedResourcesRequestsCount() < maxRequestsBeforeFirstTest) {
			logger
					.debug("context is valid concerning humanity or request count < maxRequestsBeforeFirstTest");

			return true;
		} else {
			logger
					.debug("context is not valid concerning humanity and request count > maxRequestsBeforeFirstTest");
			return false;
		}
	}

	private boolean isContextValidConcerningReTest(
			CaptchaSecurityContext context) {
		if (context.getHumanRestrictedResourcesRequestsCount() < maxRequestsBeforeReTest
				|| maxRequestsBeforeReTest < 0) {
			logger.debug("context is valid concerning reTest");

			return true;
		} else {
			logger.debug("context is not valid concerning reTest");

			return false;
		}
	}

	private boolean isContextValidConcerningMaxMillis(
			CaptchaSecurityContext context) {
		if (System.currentTimeMillis()
				- context.getLastPassedCaptchaDateInMillis() < maxMillisBeforeReTest
				|| maxMillisBeforeReTest < 0) {
			logger.debug("context is valid concerning maxMillis");

			return true;
		} else {
			logger.debug("context is not valid concerning maxMillis");

			return false;
		}
	}

	private void redirectToEntryPoint(FilterInvocation invocation)
			throws IOException, ServletException {
		logger
				.debug("security constraints not repected : redirecting to entry point");
		entryPoint.commence(invocation.getRequest(), invocation.getResponse());
		return;
	}

	public boolean supports(ConfigAttribute attribute) {
		if ((attribute != null)
				&& (attribute.getAttribute() != null)
				&& (attribute.getAttribute().equals(
						getRequiresHumanAfterMaxRequestsKeyword()) || attribute
						.getAttribute().equals(
								getRequiresHumanAfterMaxMillisKeyword())

				)) {
			return true;
		} else {
			return false;
		}
	}

}
