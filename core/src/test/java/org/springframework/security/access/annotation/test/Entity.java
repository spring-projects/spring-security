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

package org.springframework.security.access.annotation.test;

import org.springframework.util.Assert;


/**
 * An entity used in our generics testing.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class Entity {
    //~ Instance fields ================================================================================================

    String info;

    //~ Constructors ===================================================================================================

    public Entity(String info) {
        Assert.hasText(info, "Some information must be given!");
        this.info = info;
    }

    //~ Methods ========================================================================================================

    public String getInfo() {
        return info;
    }

    void makeLowercase() {
        this.info = info.toLowerCase();
    }

    void makeUppercase() {
        this.info = info.toUpperCase();
    }
}
