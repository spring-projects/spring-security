/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.captcha;

import org.springframework.util.Assert;


/**
 * Return false if the average time in millis between any CaptchaChannelProcessorTemplate mapped
 * urls requests is greater than the threshold value or the context is not human;<br />
 * Default keyword : <tt>REQUIRES_CAPTCHA_BELOW_AVERAGE_TIME_IN_MILLIS_REQUESTS</tt> <br>
 * Note : before first humanity check
 *
 * @author Marc-Antoine Garrigue
 * @version $Id$
 */
public class AlwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor extends CaptchaChannelProcessorTemplate {
    //~ Static fields/initializers =====================================================================================

    /** Keyword for this channelProcessor */
    public static final String DEFAULT_KEYWORD = "REQUIRES_CAPTCHA_BELOW_AVERAGE_TIME_IN_MILLIS_REQUESTS";

    //~ Constructors ===================================================================================================

    public AlwaysTestBelowAverageTimeInMillisBetweenRequestsChannelProcessor() {
        this.setKeyword(DEFAULT_KEYWORD);
    }

    //~ Methods ========================================================================================================

    /**
     * Verify that threshold is &gt; 0
     *
     * @throws Exception if false
     */
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        Assert.isTrue(getThreshold() > 0, "thresold must be > 0");
    }

    /**
     * 
     */
    boolean isContextValidConcerningHumanity(CaptchaSecurityContext context) {
        int req = context.getHumanRestrictedResourcesRequestsCount();
        float thresold = getThreshold();
        float duration = System.currentTimeMillis() - context.getLastPassedCaptchaDateInMillis();
        float average;

        if (req == 0) {
            average = thresold + 1;
        } else {
            average = duration / req;
        }

        if (context.isHuman() && (average > thresold)) {
            logger.debug("context is valid : average time between requests < threshold && is human");

            return true;
        } else {
            logger.debug("context is not valid : average time between requests > threshold or is not human");

            return false;
        }
    }
}
