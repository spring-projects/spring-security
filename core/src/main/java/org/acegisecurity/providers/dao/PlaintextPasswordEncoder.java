/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.dao;

/**
 * <p>
 * Plaintext implementation of PasswordEncoder.
 * </p>
 *
 * @author colin sampaleanu
 * @version $Id$
 */
public class PlaintextPasswordEncoder implements PasswordEncoder {
  
    //~ Instance fields ========================================================
    private boolean ignorePasswordCase = false;
  
    //~ Methods ================================================================
    
    /**
     * Indicates whether the password comparison is case sensitive. Defaults to
     * <code>false</code>, meaning an exact case match is required.
     *
     * @param ignorePasswordCase set to <code>true</code> for less stringent
     *        comparison
     */
    public void setIgnorePasswordCase(boolean ignorePasswordCase) {
        this.ignorePasswordCase = ignorePasswordCase;
    }

    public boolean isIgnorePasswordCase() {
        return ignorePasswordCase;
    }

    /* (non-Javadoc)
     * @see net.sf.acegisecurity.providers.dao.PasswordEncoder#isPasswordValid(java.lang.String, java.lang.String, java.lang.Object)
     */
    public boolean isPasswordValid(String encPass, String rawPass, Object saltSource) {
      
        String pass1 = "" + encPass;
        String pass2 = "" + rawPass;

        if (!ignorePasswordCase) {
            return pass1.equals(pass2);
        } else {
            return pass1.equalsIgnoreCase(pass2);
        }
    }

    /* (non-Javadoc)
     * @see net.sf.acegisecurity.providers.dao.PasswordEncoder#encodePassword(java.lang.String, java.lang.Object)
     */
    public String encodePassword(String rawPass, Object saltSource) {
        return rawPass;
    }
}
