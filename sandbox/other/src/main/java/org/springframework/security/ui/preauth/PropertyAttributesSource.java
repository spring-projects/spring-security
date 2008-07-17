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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Source of the attributes associated with pre-authenticated authentication request. The attributes
 * can be supplied in the <tt>attributes</tt> property (configuration file).
 * 
 * @author Valery Tydykov
 * 
 */
public class PropertyAttributesSource implements AttributesSource {

    /**
     * Logger for this class and subclasses
     */
    protected final Log logger = LogFactory.getLog(this.getClass());

    private Map attributes = new HashMap();

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.ui.preauth.AttributesSource#obtainAttributes(javax.servlet.http.HttpServletRequest)
     */
    public Map obtainAttributes(HttpServletRequest request) {
        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Obtained attributes=[" + attributes + "] from property");
        }

        return attributes;
    }

    /**
     * @return the attributes
     */
    public Map getAttributes() {
        return this.attributes;
    }

    /**
     * @param attributes the attributes to set
     */
    public void setAttributes(Map attributes) {
        this.attributes = attributes;
    }
}
