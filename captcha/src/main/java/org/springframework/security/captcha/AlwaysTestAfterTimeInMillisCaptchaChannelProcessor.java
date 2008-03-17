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

/**
 * Return false if the time in millis since the last captcha test is less than the threshold;<br/>
 * Default keyword : <tt>REQUIRES_CAPTCHA_AFTER_THRESHOLD_IN_MILLIS</tt>.
 *
 * @author Marc-Antoine Garrigue
 * @version $Id$
 */
public class AlwaysTestAfterTimeInMillisCaptchaChannelProcessor extends CaptchaChannelProcessorTemplate {
    //~ Static fields/initializers =====================================================================================

    /** Keyword for this channelProcessor */
    public static final String DEFAULT_KEYWORD = "REQUIRES_CAPTCHA_AFTER_THRESHOLD_IN_MILLIS";

    //~ Constructors ===================================================================================================

    public AlwaysTestAfterTimeInMillisCaptchaChannelProcessor() {

        this.setKeyword(DEFAULT_KEYWORD);
    }

    //~ Methods ========================================================================================================

    /**
     * Returns false if the time (in milliseconds) since the last captcha validation is greater than the 
     * threshold value. 
     *
     * @param context the CaptchaSecurityContext
     *
     */
    boolean isContextValidConcerningHumanity(CaptchaSecurityContext context) {
        if ((System.currentTimeMillis() - context.getLastPassedCaptchaDateInMillis()) < getThreshold()) {
            logger.debug("context is valid : current time - last passed captcha date < threshold");

            return true;
        } else {
            logger.debug("context is not valid : current time - last passed captcha date > threshold");

            return false;
        }
    }
}
