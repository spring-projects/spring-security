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
package org.springframework.security.ui.preauth;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.ui.WebAuthenticationDetails;

/**
 * A holder of selected HTTP details related to a web authentication request.
 * <p>
 * Has additional <tt>attributes</tt> property.
 * 
 * @author Valery Tydykov
 */
public class AuthenticationDetailsImpl extends WebAuthenticationDetails {
    public AuthenticationDetailsImpl(HttpServletRequest request) {
        super(request);
    }

    private Map attributes = new HashMap();

    /**
     * @return the attributes
     */
    public Map getAttributes() {
        return attributes;
    }

    /**
     * @param attributes the attributes to set
     */
    public void setAttributes(Map attributes) {
        this.attributes = attributes;
    }
}
