<%@ include file="/WEB-INF/jsp/include.jsp" %>

<html>
<head><title>Your Contacts</title></head>
<body>
<h1><authz:authentication operation="username"/>'s Contacts</h1>
<P>
<table cellpadding=3 border=0>
<tr><td><b>id</b></td><td><b>Name</b></td><td><b>Email</b></td></tr>
<c:forEach var="contact" items="${model.contacts}">
  <tr>
  <td>
      <c:out value="${contact.id}"/>
  </td>
  <td>
      <c:out value="${contact.name}"/>
  </td>
  <td>
      <c:out value="${contact.email}"/>
  </td>
  <authz:acl domainObject="${contact}" hasPermission="16,1">
    <td><A HREF="<c:url value="del.htm"><c:param name="contactId" value="${contact.id}"/></c:url>">Del</A></td>
  </authz:acl>
  <authz:acl domainObject="${contact}" hasPermission="1">
    <td><A HREF="<c:url value="adminPermission.htm"><c:param name="contactId" value="${contact.id}"/></c:url>">Admin Permission</A></td>
  </authz:acl>
  </tr>
</c:forEach>
</table>
<p><a href="<c:url value="add.htm"/>">Add</a>   <p><a href="<c:url value="../logoff.jsp"/>">Logoff</a> (also clears any remember-me cookie)
</body>
</html>
