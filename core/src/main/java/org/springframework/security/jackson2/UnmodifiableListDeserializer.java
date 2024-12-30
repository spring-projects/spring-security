/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.jackson2;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Custom deserializer for {@link UnmodifiableListMixin}.
 *
 * @author Rob Winch
 * @author Hyunmin Choi
 * @since 5.0.2
 * @see UnmodifiableListMixin
 */
class UnmodifiableListDeserializer extends AbstractUnmodifiableCollectionDeserializer<List> {

	@Override
	List createUnmodifiableCollection(Collection<Object> values) {
		return Collections.unmodifiableList(new ArrayList<>(values));
	}

}
