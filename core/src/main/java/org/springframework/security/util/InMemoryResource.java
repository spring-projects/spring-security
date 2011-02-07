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
import org.springframework.util.Assert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;


/**
 * An in memory implementation of Spring's {@link org.springframework.core.io.Resource} interface.
 * <p>Used to create a bean factory from an XML string, rather than a file.</p>
 *
 * @author Luke Taylor
 */
public class InMemoryResource extends AbstractResource {
    //~ Instance fields ================================================================================================

    private final byte[] source;
    private final String description;

    //~ Constructors ===================================================================================================

    public InMemoryResource(String source) {
        this(source.getBytes());
    }

    public InMemoryResource(byte[] source) {
        this(source, null);
    }

    public InMemoryResource(byte[] source, String description) {
        Assert.notNull(source);
        this.source = source;
        this.description = description;
    }

    //~ Methods ========================================================================================================

    public String getDescription() {
        return description;
    }

    public InputStream getInputStream() throws IOException {
        return new ByteArrayInputStream(source);
    }

    public int hashCode() {
        return 1;
    }

    public boolean equals(Object res) {
        if (!(res instanceof InMemoryResource)) {
            return false;
        }

        return Arrays.equals(source, ((InMemoryResource)res).source);
    }
}
