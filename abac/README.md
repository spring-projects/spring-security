**ABAC (Attribute-Based Access Control) Support for Spring**

Sometimes ACL is too much and RBAC is not enough.
Attribute-Based Access Control is something in between and allows more fine granulate "access rules"  

Inspired by articles like
[ATTRIBUTE BASED ACCESS CONTROL (ABAC) - OVERVIEW][1] by [NIST.gov](NIST.gov) and [Wikipedia][2]

**Idea**

Define your policy depending on
- subject
- resource
- action
- environment

Example:
subject.age>21 and action == 'CREATE_BLOG'

Example: Policy as json:

```json
[
 	{
 		"name": "Edit if member of organisation",
 		"type": "",
 		"description": "Admin can access everything",
 		"applicable": "subject.organisation == 'MyOrg' and action == 'EDIT'",
 		"condition": "true"
 	}
 ]
 ```


[1]:http://csrc.nist.gov/projects/abac/
[2]:https://en.wikipedia.org/wiki/Attribute-Based_Access_Control


