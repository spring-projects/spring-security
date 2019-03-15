/*
 * Copyright 2002-2016 the original author or authors.
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
package sample.data;

import java.util.Calendar;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class ActiveWebSocketUser {
	@Id
	private String id;

	private String username;

	private Calendar connectionTime;

	public ActiveWebSocketUser() {
	}

	public ActiveWebSocketUser(String id, String username, Calendar connectionTime) {
		super();
		this.id = id;
		this.username = username;
		this.connectionTime = connectionTime;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public Calendar getConnectionTime() {
		return connectionTime;
	}

	public void setConnectionTime(Calendar connectionTime) {
		this.connectionTime = connectionTime;
	}

}
