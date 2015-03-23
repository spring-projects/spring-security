package org.springframework.security.acls.sid;

import org.springframework.security.acls.model.Sid;

/**
 * This class is example of custom {@link Sid} implementation
 * @author Mikhail Stryzhonok
 */
public class CustomSid implements Sid {

	private String sid;

	public CustomSid(String sid) {
		this.sid = sid;
	}

	public String getSid() {
		return sid;
	}

	public void setSid(String sid) {
		this.sid = sid;
	}
}
