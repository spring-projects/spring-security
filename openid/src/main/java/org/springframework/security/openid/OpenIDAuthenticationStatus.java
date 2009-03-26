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
package org.springframework.security.openid;

import java.io.ObjectStreamException;
import java.io.Serializable;


/**
 * Based on JanRain status codes
 *
 * @author JanRain Inc.
 * @author Robin Bramley, Opsera Ltd
 */
public class OpenIDAuthenticationStatus implements Serializable {
    //~ Static fields/initializers =====================================================================================

    private static final long serialVersionUID = -998877665544332211L;
    private static int nextOrdinal = 0;

    /** This code indicates a successful authentication request */
    public static final OpenIDAuthenticationStatus SUCCESS = new OpenIDAuthenticationStatus("success");

    /** This code indicates a failed authentication request */
    public static final OpenIDAuthenticationStatus FAILURE = new OpenIDAuthenticationStatus("failure");

    /** This code indicates the server reported an error */
    public static final OpenIDAuthenticationStatus ERROR = new OpenIDAuthenticationStatus("error");

    /** This code indicates that the user needs to do additional work to prove their identity */
    public static final OpenIDAuthenticationStatus SETUP_NEEDED = new OpenIDAuthenticationStatus("setup needed");

    /** This code indicates that the user cancelled their login request */
    public static final OpenIDAuthenticationStatus CANCELLED = new OpenIDAuthenticationStatus("cancelled");
    private static final OpenIDAuthenticationStatus[] PRIVATE_VALUES = {SUCCESS, FAILURE, ERROR, SETUP_NEEDED, CANCELLED};

    //~ Instance fields ================================================================================================

    private String name;
    private final int ordinal = nextOrdinal++;

    //~ Constructors ===================================================================================================

    private OpenIDAuthenticationStatus(String name) {
        this.name = name;
    }

    //~ Methods ========================================================================================================

    private Object readResolve() throws ObjectStreamException {
        return PRIVATE_VALUES[ordinal];
    }

    public String toString() {
        return name;
    }
}
