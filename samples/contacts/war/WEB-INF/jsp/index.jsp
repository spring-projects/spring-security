<%@ include file="/WEB-INF/jsp/include.jsp" %>

<html>
<head><title>Your Contacts</title></head>
<body>
<h1><c:out value="${model.user}"/>'s Contacts</h1>
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
  <authz:authorize ifAllGranted="ROLE_SUPERVISOR">
    <td><A HREF="del.htm?id=<c:out value="${contact.id}"/>">Del</A></td>
  </authz:authorize>
  </tr>
</c:forEach>
</table>
<p><A HREF="add.htm">Add</a>   <A HREF="../logoff.jsp">Logoff</A>
</body>
</html>
