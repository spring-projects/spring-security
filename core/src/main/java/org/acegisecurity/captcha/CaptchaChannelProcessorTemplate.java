/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

import java.io.IOException;

import java.util.Iterator;

import javax.servlet.ServletException;


/**
 * <p>
 * CaptchaChannel template : Ensures the user has enough human privileges by
 * review of the {@link CaptchaSecurityContext} and using an abstract routine
 * {@link #isContextValidConcerningHumanity(CaptchaSecurityContext)}
 * (implemented by sub classes)
 * </p>
 * 
 * <P>
 * The component uses 2 main parameters for its configuration :
 * 
 * <ul>
 * <li>
 * a keyword to be mapped to urls in the {@link
 * net.sf.acegisecurity.securechannel.ChannelProcessingFilter} configuration<br>
 * default value provided by sub classes.
 * </li>
 * <li>
 * and a thresold : used by the routine {@link
 * #isContextValidConcerningHumanity(CaptchaSecurityContext)} to evaluate
 * whether the {@link CaptchaSecurityContext} is valid default value = 0
 * </li>
 * </ul>
 * </p>
 *
 * @author marc antoine Garrigue
 * @version $Id$
 */
public abstract class CaptchaChannelProcessorTemplate
    implements ChannelProcessor, InitializingBean {
    //~ Instance fields ========================================================

    protected Log logger = LogFactory.getLog(this.getClass());
    private ChannelEntryPoint entryPoint;
    private String keyword = null;
    private int thresold = 0;

    //~ Methods ================================================================

    public void setEntryPoint(ChannelEntryPoint entryPoint) {
        this.entryPoint = entryPoint;
    }

    public ChannelEntryPoint getEntryPoint() {
        return entryPoint;
    }

    public void setKeyword(String keyword) {
        this.keyword = keyword;
    }

    public String getKeyword() {
        return keyword;
    }

    public void setThresold(int thresold) {
        this.thresold = thresold;
    }

    public int getThresold() {
        return thresold;
    }

    /**
     * Verify if entryPoint and keyword are ok
     *
     * @throws Exception if not
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(entryPoint, "entryPoint required");
        Assert.hasLength(keyword, "keyword required");
    }

    public void decide(FilterInvocation invocation,
        ConfigAttributeDefinition config) throws IOException, ServletException {
        if ((invocation == null) || (config == null)) {
            throw new IllegalArgumentException("Nulls cannot be provided");
        }

        CaptchaSecurityContext context = null;
        context = (CaptchaSecurityContext) SecurityContextHolder.getContext();

        Iterator iter = config.getConfigAttributes();

        while (iter.hasNext()) {
            ConfigAttribute attribute = (ConfigAttribute) iter.next();

            if (supports(attribute)) {
                logger.debug("supports this attribute : " + attribute);

                if (!isContextValidConcerningHumanity(context)) {
                    logger.debug(
                        "context is not allowed to access ressource, redirect to captcha entry point");
                    redirectToEntryPoint(invocation);
                } else {
                    logger.debug(
                        "has been successfully checked this keyword, increment request count");
                    context.incrementHumanRestrictedRessoucesRequestsCount();
                }
            } else {
                logger.debug("do not support this attribute");
            }
        }
    }

    public boolean supports(ConfigAttribute attribute) {
        if ((attribute != null) && (keyword.equals(attribute.getAttribute()))) {
            return true;
        } else {
            return false;
        }
    }

    abstract boolean isContextValidConcerningHumanity(
        CaptchaSecurityContext context);

    private void redirectToEntryPoint(FilterInvocation invocation)
        throws IOException, ServletException {
        if (logger.isDebugEnabled()) {
            logger.debug("context is not valid : redirecting to entry point");
        }

        entryPoint.commence(invocation.getRequest(), invocation.getResponse());
    }
}
