/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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
 */
public class Contact implements Serializable {
    //~ Instance fields ================================================================================================

    private Long id;
    private String email;
    private String name;

    //~ Constructors ===================================================================================================

    public Contact(String name, String email) {
        this.name = name;
        this.email = email;
    }

    public Contact() {}

    //~ Methods ========================================================================================================

    /**
     * @return Returns the email.
     */
    public String getEmail() {
        return email;
    }

    /**
     * @return Returns the id.
     */
    public Long getId() {
        return id;
    }

    /**
     * @return Returns the name.
     */
    public String getName() {
        return name;
    }

    /**
     * @param email The email to set.
     */
    public void setEmail(String email) {
        this.email = email;
    }

    public void setId(Long id) {
        this.id = id;
    }

    /**
     * @param name The name to set.
     */
    public void setName(String name) {
        this.name = name;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString() + ": ");
        sb.append("Id: " + this.getId() + "; ");
        sb.append("Name: " + this.getName() + "; ");
        sb.append("Email: " + this.getEmail());

        return sb.toString();
    }
}
