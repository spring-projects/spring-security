<%@ include file="/WEB-INF/jsp/include.jsp" %>

<html>
<head><title>Your Contacts</title></head>
<body>
<h1><security:authentication property="principal.username"/>'s Contacts</h1>
<P>
<table cellpadding=3 border=0>
<tr><td><b>id</b></td><td><b>Name</b></td><td><b>Email</b></td></tr>
<c:forEach var="contact" items="${model.contacts}" >
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
  <c:if test="${model.hasDeletePermission[contact]}">
    <td><a href="<c:url value="del.htm"><c:param name="contactId" value="${contact.id}"/></c:url>">Del</a></td>
  </c:if>
  <c:if test="${model.hasAdminPermission[contact]}">
    <td><a href="<c:url value="adminPermission.htm"><c:param name="contactId" value="${contact.id}"/></c:url>">Admin Permission</a></td>
  </c:if>
  </tr>
</c:forEach>
</table>
<p><a href="<c:url value="add.htm"/>">Add</a>   <p><a href="<c:url value="../j_spring_security_logout"/>">Logoff</a> (also clears any remember-me cookie)
</body>
</html>
