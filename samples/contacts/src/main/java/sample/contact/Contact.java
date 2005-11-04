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

package sample.contact;

import java.io.Serializable;


/**
 * Represents a contact.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class Contact implements Serializable {
    //~ Instance fields ========================================================

    private Long id;
    private String email;
    private String name;

    //~ Constructors ===========================================================

    public Contact(String name, String email) {
        this.name = name;
        this.email = email;
    }

    public Contact() {}

    //~ Methods ================================================================

    /**
     * DOCUMENT ME!
     *
     * @param email The email to set.
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * DOCUMENT ME!
     *
     * @return Returns the email.
     */
    public String getEmail() {
        return email;
    }

    public void setId(Long id) {
        this.id = id;
    }

    /**
     * DOCUMENT ME!
     *
     * @return Returns the id.
     */
    public Long getId() {
        return id;
    }

    /**
     * DOCUMENT ME!
     *
     * @param name The name to set.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * DOCUMENT ME!
     *
     * @return Returns the name.
     */
    public String getName() {
        return name;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString() + ": ");
        sb.append("Id: " + this.getId() + "; ");
        sb.append("Name: " + this.getName() + "; ");
        sb.append("Email: " + this.getEmail());

        return sb.toString();
    }
}
