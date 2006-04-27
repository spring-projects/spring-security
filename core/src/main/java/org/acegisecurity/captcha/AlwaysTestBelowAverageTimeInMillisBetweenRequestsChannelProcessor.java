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

package org.acegisecurity.captcha;

import org.springframework.util.Assert;


/**
 * <p>
 * return false if thresold is lower than average time millis between any
 * CaptchaChannelProcessorTemplate mapped urls requests and is human;<br>
 * Default keyword : REQUIRES_CAPTCHA_BELOW_AVERAGE_TIME_IN_MILLIS_REQUESTS <br>
 * Note : before first humanity check
 * </p>
 *
 * @author Marc-Antoine Garrigue
 * @version $Id$
 */
public class AlwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor
    extends CaptchaChannelProcessorTemplate {
    //~ Static fields/initializers =============================================

    /** Keyword for this channelProcessor */
    public static final String DEFAULT_KEYWORD = "REQUIRES_CAPTCHA_BELOW_AVERAGE_TIME_IN_MILLIS_REQUESTS";

    //~ Constructors ===========================================================

    /**
     * Constructor
     */
    public AlwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor() {
        super();
        this.setKeyword(DEFAULT_KEYWORD);
    }

    //~ Methods ================================================================

    /**
     * Verify if thresold is &gt; 0
     *
     * @throws Exception if false
     */
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        Assert.isTrue(getThresold() > 0, "thresold must be > 0");
    }

    /**
     * Verify wheter the context is valid concerning humanity
     *
     * @param context
     *
     * @return true if valid, false otherwise
     */
    boolean isContextValidConcerningHumanity(CaptchaSecurityContext context) {
        int req = context.getHumanRestrictedResourcesRequestsCount();
        float thresold = getThresold();
        float duration = System.currentTimeMillis()
            - context.getLastPassedCaptchaDateInMillis();
        float average;

        if (req == 0) {
            average = thresold + 1;
        } else {
            average = duration / req;
        }

        if (context.isHuman() && (average > thresold)) {
            logger.debug(
                "context is valid : average time between requests < thresold && is human");

            return true;
        } else {
            logger.debug(
                "context is not valid : request count > thresold or is not human");

            return false;
        }
    }
}
