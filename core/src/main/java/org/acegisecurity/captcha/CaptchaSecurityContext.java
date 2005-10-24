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

import net.sf.acegisecurity.context.SecurityContext;


/**
 * Interface that add humanity concerns to the SecurityContext
 *
 * @author marc antoine garrigue
 */
public interface CaptchaSecurityContext extends SecurityContext {
    //~ Methods ================================================================

    /**
     * set human attribute, should called after captcha validation.
     */
    void setHuman();

    /**
     * DOCUMENT ME!
     *
     * @return true if the current user has already passed a captcha.
     */
    boolean isHuman();

    /**
     * DOCUMENT ME!
     *
     * @return number of human restricted resources requests since the last
     *         passed captcha.
     */
    int getHumanRestrictedResourcesRequestsCount();

    /**
     * DOCUMENT ME!
     *
     * @return the date of the last passed Captcha in millis, 0 if the user
     *         never passed captcha.
     */
    long getLastPassedCaptchaDateInMillis();

    /**
     * Method to increment the human Restricted Resrouces Requests Count;
     */
    void incrementHumanRestrictedRessoucesRequestsCount();
}
