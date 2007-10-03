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

package org.springframework.security.util;

import org.springframework.core.io.AbstractResource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * An in memory implementation of Spring's {@link org.springframework.core.io.Resource} interface.
 * <p>Used to create a bean factory from an XML string, rather than a file.</p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class InMemoryResource extends AbstractResource {
    //~ Instance fields ================================================================================================

    private ByteArrayInputStream in;
    private String description;

    //~ Constructors ===================================================================================================

    public InMemoryResource(byte[] source) {
        this(source, null);
    }

    public InMemoryResource(byte[] source, String description) {
        in = new ByteArrayInputStream(source);
        this.description = description;
    }

    //~ Methods ========================================================================================================

    public String getDescription() {
        return (description == null) ? in.toString() : description;
    }

    public InputStream getInputStream() throws IOException {
        return in;
    }
}
