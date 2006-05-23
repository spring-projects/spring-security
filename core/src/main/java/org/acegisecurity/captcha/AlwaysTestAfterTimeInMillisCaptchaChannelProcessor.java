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

package org.acegisecurity.captcha;

/**
 * <p>return false if thresold is greater than millis since last captcha test has occured;<br>
 * Default keyword : REQUIRES_CAPTCHA_AFTER_THRESOLD_IN_MILLIS</p>
 *
 * @author Marc-Antoine Garrigue
 * @version $Id$
 */
public class AlwaysTestAfterTimeInMillisCaptchaChannelProcessor extends CaptchaChannelProcessorTemplate {
    //~ Static fields/initializers =====================================================================================

    /** Keyword for this channelProcessor */
    public static final String DEFAULT_KEYWORD = "REQUIRES_CAPTCHA_AFTER_THRESOLD_IN_MILLIS";

    //~ Constructors ===================================================================================================

/**
     * Constructor
     */
    public AlwaysTestAfterTimeInMillisCaptchaChannelProcessor() {
        super();
        this.setKeyword(DEFAULT_KEYWORD);
    }

    //~ Methods ========================================================================================================

    /**
     * Verify wheter the context is valid concerning humanity
     *
     * @param context the CaptchaSecurityContext
     *
     * @return true if valid, false otherwise
     */
    boolean isContextValidConcerningHumanity(CaptchaSecurityContext context) {
        if ((System.currentTimeMillis() - context.getLastPassedCaptchaDateInMillis()) < getThresold()) {
            logger.debug("context is valid : last passed captcha date - current time < thresold");

            return true;
        } else {
            logger.debug("context is not valid : last passed captcha date - current time > thresold");

            return false;
        }
    }
}
