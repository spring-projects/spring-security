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

package org.springframework.security.ui.cas;

import org.springframework.beans.factory.InitializingBean;


/**
 * Stores properties related to this CAS service.<P>Each web application capable of processing CAS tickets is known
 * as a service. This class stores the properties that are relevant to the local CAS service, being the application
 * that is being secured by the Acegi Security System for Spring.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ServiceProperties implements InitializingBean {
    //~ Instance fields ================================================================================================

    private String service;
    private boolean sendRenew = false;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        if ((service == null) || "".equals(service)) {
            throw new IllegalArgumentException("service must be specified");
        }
    }

    /**
     * Represents the service the user is authenticating to.<p>This service is the callback URL belonging to
     * the local Acegi Security System for Spring secured application. For example,</p>
     *  <code>https://www.mycompany.com/application/j_acegi_cas_security_check</code>
     *
     * @return the URL of the service the user is authenticating to
     */
    public String getService() {
        return service;
    }

    /**
     * Indicates whether the <code>renew</code> parameter should be sent to the CAS login URL and CAS
     * validation URL.<p>If <code>true</code>, it will force CAS to authenticate the user again (even if the
     * user has previously authenticated). During ticket validation it will require the ticket was generated as a
     * consequence of an explicit login. High security applications would probably set this to <code>true</code>.
     * Defaults to <code>false</code>, providing automated single sign on.</p>
     *
     * @return whether to send the <code>renew</code> parameter to CAS
     */
    public boolean isSendRenew() {
        return sendRenew;
    }

    public void setSendRenew(boolean sendRenew) {
        this.sendRenew = sendRenew;
    }

    public void setService(String service) {
        this.service = service;
    }
}
