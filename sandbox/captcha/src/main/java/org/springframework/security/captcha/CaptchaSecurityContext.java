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

import org.springframework.security.context.SecurityContext;


/**
 * Interface that adds humanity concerns to the SecurityContext
 *
 * @author Marc-Antoine Garrigue
 * @version $Id$
 */
public interface CaptchaSecurityContext extends SecurityContext {
    //~ Methods ========================================================================================================

    /**
     *
     * @return the number of human restricted resources requested since the last passed captcha.
     */
    int getHumanRestrictedResourcesRequestsCount();

    /**
     *
     * @return the date of the last passed Captcha in millis, 0 if the user never passed captcha.
     */
    long getLastPassedCaptchaDateInMillis();

    /**
     * Increments the human Restricted Resources Requests Count.
     */
    void incrementHumanRestrictedResourcesRequestsCount();

    /**
     *
     * @return true if the current user has already passed a captcha.
     */
    boolean isHuman();

    /**
     * set human attribute, should be called after captcha validation.
     */
    void setHuman();
}
