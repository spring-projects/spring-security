/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.header.writers;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.web.header.Header;

/**
 * A {@link StaticHeadersWriter} that inserts headers to prevent caching.
 * Specifically it adds the following headers:
 * <ul>
 * <li>Cache-Control: no-cache, no-store, max-age=0, must-revalidate</li>
 * <li>Pragma: no-cache</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class CacheControlHeadersWriter extends StaticHeadersWriter {

    /**
     * Creates a new instance
     */
    public CacheControlHeadersWriter() {
        super(createHeaders());
    }

    private static List<Header> createHeaders() {
        List<Header> headers = new ArrayList<Header>(2);
        headers.add(new Header("Cache-Control","no-cache, no-store, max-age=0, must-revalidate"));
        headers.add(new Header("Pragma","no-cache"));
        headers.add(new Header("Expires","0"));
        return headers;
    }
}
