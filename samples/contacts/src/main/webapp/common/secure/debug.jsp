<%@ page import="net.sf.acegisecurity.context.Context" %>
<%@ page import="net.sf.acegisecurity.context.ContextHolder" %>
<%@ page import="net.sf.acegisecurity.context.SecureContext" %>
<%@ page import="net.sf.acegisecurity.Authentication" %>
<%@ page import="net.sf.acegisecurity.GrantedAuthority" %>
<%@ page import="net.sf.acegisecurity.adapters.AuthByAdapter" %>

<% Context context = ContextHolder.getContext();
if (context != null) { %>
	Context on ContextHolder is of type: <%= context.getClass().getName() %><BR><BR>
	
<%	if (context instanceof SecureContext) { %>
		The Context implements SecureContext.<BR><BR>
<%		SecureContext sc = (SecureContext) context;
		
		Authentication auth = sc.getAuthentication();
		if (auth != null) { %>
			Authentication object is of type: <%= auth.getClass().getName() %><BR><BR>
			Authentication object as a String: <%= auth.toString() %><BR><BR>
			
			Authentication object holds the following granted authorities:<BR><BR>
<%			GrantedAuthority[] granted = auth.getAuthorities();
			for (int i = 0; i < granted.length; i++) { %>
				<%= granted[i].toString() %> (getAuthority(): <%= granted[i].getAuthority() %>)<BR>
<%			}

			if (auth instanceof AuthByAdapter) { %>
				<BR><B>SUCCESS! Your container adapter appears to be properly configured!</B><BR><BR>
<%			} else { %>
				<BR><B>SUCCESS! Your web filter appears to be properly configured!</B><BR>
<%			}
			
		} else { %>
			Authentication object is null.<BR>
			This is an error and your container adapter will not operate properly until corrected.<BR><BR>
<%		}
	} else { %>
		<B>ContextHolder does not contain a SecureContext.</B><BR>
		This is an error and your container adapter will not operate properly until corrected.<BR><BR>
<%	}
} else { %>
	<B>ContextHolder on ContextHolder is null.</B><BR>
	This indicates improper setup of the container adapter. Refer to the reference documentation.<BR>
	Also ensure the correct subclass of AbstractMvcIntegrationInterceptor is being used for your container.<BR>
<%}
%>

