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

import org.springframework.dao.DataAccessException;


/**
 * <p>
 * Describes authentication operations on a password, so that digest algorithms
 * can be abstracted
 * </p>
 *
 * @author colin sampaleanu
 * @version $Id$
 */
public interface PasswordEncoder {
    //~ Methods ================================================================

    public boolean isPasswordValid(String encPass, String rawPass,
        Object saltSource, boolean ignorePasswordCase)
        throws DataAccessException;

    public String encodePassword(String rawPass, Object saltSource);
}
