 /*
  * Authconfig - client authentication configuration program
  * Copyright (c) 2002,2003 Red Hat, Inc.
  *
  * This is free software; you can redistribute it and/or modify it
  * under the terms of the GNU General Public License as published by
  * the Free Software Foundation; either version 2 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful, but
  * WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
  *
  */

#include "config.h"
#include <sys/types.h>
#include <Python.h>
#include <glib.h>
#include "authinfo.h"

void initauthconfig(void);

#define authInfoObject_Check(op) PyObject_TypeCheck(op, &authInfoObjectType)
extern PyTypeObject authInfoObjectType;
static PyObject *authconfig_write(PyObject *self, PyObject *args,
				  PyObject *kwargs);
static PyObject *authconfig_post(PyObject *self, PyObject *args,
				 PyObject *kwargs);
static PyObject *authconfig_differs(PyObject *self, PyObject *args,
				    PyObject *kwargs);
static PyObject *authconfig_join(PyObject *self, PyObject *args,
				 PyObject *kwargs);
static struct authInfoObject *authconfig_copy(PyObject *self, PyObject *args,
					      PyObject *kwargs);
static PyObject *authconfig_update(PyObject *self);

/* Define a mapping for the fields in the authInfo structure we want to
 * expose through python. */
enum datatype {tfvalue, svalue};
#define TF_FIELD(x) \
	{G_STRINGIFY(x), tfvalue, G_STRUCT_OFFSET(struct authInfoType, x),}
#define S_FIELD(x) \
	{G_STRINGIFY(x), svalue, G_STRUCT_OFFSET(struct authInfoType, x),}
static struct {
	const char *name;
	enum datatype type;
	size_t offset;
} map[] = {
	S_FIELD(hesiodLHS),
	S_FIELD(hesiodRHS),
	S_FIELD(ldapServer),
	S_FIELD(ldapBaseDN),
	S_FIELD(kerberosRealm),
	S_FIELD(kerberosKDC),
	S_FIELD(kerberosAdminServer),
	S_FIELD(nisServer),
	S_FIELD(nisDomain),
	S_FIELD(smbWorkgroup),
	S_FIELD(smbRealm),
	S_FIELD(smbServers),
	S_FIELD(smbSecurity),
	S_FIELD(smbIdmapUid),
	S_FIELD(smbIdmapGid),
	S_FIELD(winbindSeparator),
	S_FIELD(winbindTemplateHomedir),
	S_FIELD(winbindTemplatePrimaryGroup),
	S_FIELD(winbindTemplateShell),
	TF_FIELD(winbindUseDefaultDomain),
	TF_FIELD(enableCache),
	TF_FIELD(enableDB),
	TF_FIELD(enableDirectories),
	TF_FIELD(enableHesiod),
	TF_FIELD(enableLDAP),
	TF_FIELD(enableLDAPS),
	TF_FIELD(enableNIS),
	/* TF_FIELD(enableNIS3), */
	/* TF_FIELD(enableDBbind), */
	/* TF_FIELD(enableDBIbind), */
	/* TF_FIELD(enableHesiodbind), */
	/* TF_FIELD(enableLDAPbind), */
	/* TF_FIELD(enableOdbcbind), */
	TF_FIELD(enableWinbind),
	TF_FIELD(enableWINS),

	/* TF_FIELD(enableAFS), */
	/* TF_FIELD(enableAFSKerberos), */
	/* TF_FIELD(enableBigCrypt), */
	/* TF_FIELD(enableEPS), */
	TF_FIELD(enableKerberos),
	TF_FIELD(enableLDAPAuth),
	TF_FIELD(enableMD5),
	/* TF_FIELD(enableOTP), */
	TF_FIELD(enableShadow),
	TF_FIELD(enableSMB),
	S_FIELD(joinUser),
	S_FIELD(joinPassword),
};

struct authInfoObject {
	PyObject_HEAD
	struct authInfoType *info;
};

/* Destroy an authInfoObject. */
static void
authInfoObject_destroy(struct authInfoObject *self)
{
	authInfoFree(self->info);
	self->info = NULL;
	PyMem_DEL(self);
}

/* The svalue method.  Thankfully, we don't have to parse this. */
static PyObject *
authInfoObject_print(PyObject *self, PyObject *args)
{
	struct authInfoObject *info;
	char *ret_string, *tmp;
	PyObject *ret;
	char **p;
	gboolean *b;
	int i;
	if (authInfoObject_Check(self)) {
		info = (struct authInfoObject *)self;
	} else {
		PyErr_SetString(PyExc_TypeError, "expected authInfoObject");
		return NULL;
	}

	ret_string = g_strdup("");
	for (i = 0; i < G_N_ELEMENTS(map); i++) {
		switch(map[i].type) {
			case tfvalue:
				b = G_STRUCT_MEMBER_P(info->info,
						      map[i].offset);
				tmp = g_strdup_printf("%s  %s = %d\n",
						      ret_string, 
						      map[i].name,
						      *b);
				break;
			case svalue:
				p = G_STRUCT_MEMBER_P(info->info,
						      map[i].offset);
				if (*p) {
					tmp = g_strdup_printf("%s  %s = '%s'\n",
							      ret_string,
							      map[i].name,
							      *p);
				} else {
					tmp = g_strdup_printf("%s  %s = (null)\n",
							      ret_string,
							      map[i].name);
				}
				break;
			default:
				tmp = g_strconcat(ret_string,
					       	  "Ouch!  What do you do?",
						  NULL);
				break;
		}
		g_free(ret_string);
		ret_string = tmp;
	}
	tmp = g_strdup_printf("[\n%s]", ret_string);
	g_free(ret_string);

	ret = Py_BuildValue("s", tmp);
	g_free(tmp);
	return ret;
}

static int
authInfoObject_setattr(PyObject *self, const char *attribute, PyObject *args)
{
	struct authInfoObject *info;
	int i;
	char **p;
	gboolean *b;
	if (authInfoObject_Check(self)) {
		info = (struct authInfoObject *)self;
	} else {
		PyErr_SetString(PyExc_TypeError, "expected authInfoObject");
		return -1;
	}
	for (i = 0; i < G_N_ELEMENTS(map); i++) {
		if (strcmp(attribute, map[i].name) == 0) {
			switch(map[i].type) {
				case tfvalue:
					b = G_STRUCT_MEMBER_P(info->info,
							      map[i].offset);
					*b = (args != NULL) &&
					     PyObject_IsTrue(args);
					authInfoUpdate(info->info);
					return 0;
					break;
				case svalue:
					p = G_STRUCT_MEMBER_P(info->info,
							      map[i].offset);
					if (*p != NULL) {
						g_free(*p);
						*p = NULL;
					}
					if (PyString_Check(args)) {
						*p = g_strdup(PyString_AsString(args));
						authInfoUpdate(info->info);
						return 0;
					} else
					if (PyNumber_Check(args)) {
						*p = g_strdup_printf("%ld", PyLong_AsLong(PyNumber_Long((args))));
						authInfoUpdate(info->info);
						return 0;
					} else {
						authInfoUpdate(info->info);
						return 0;
					}
					break;
			}
		}
	}
	PyErr_SetString(PyExc_KeyError, "no such field");
	return -1;
}

static PyMethodDef authconfig_methods[] = {
	{"write", (PyCFunction)authconfig_write,
	 METH_VARARGS | METH_KEYWORDS},
	{"copy", (PyCFunction)authconfig_copy,
	 METH_VARARGS | METH_KEYWORDS},
	{"post", (PyCFunction)authconfig_post,
	 METH_VARARGS | METH_KEYWORDS},
	{"update", (PyCFunction)authconfig_update,
	 METH_NOARGS},
	{"differs", (PyCFunction)authconfig_differs,
	 METH_VARARGS | METH_KEYWORDS},
	{"join", (PyCFunction)authconfig_join,
	 METH_VARARGS | METH_KEYWORDS},
	{NULL, NULL, 0},
};

static PyObject *
authInfoObject_getattr(PyObject *self, char *attribute)
{
	int i;
	struct authInfoObject *info;
	char **p;
	gboolean *b;
	if (authInfoObject_Check(self)) {
		info = (struct authInfoObject *)self;
	} else {
		PyErr_SetString(PyExc_TypeError, "expected authInfoObject");
		return NULL;
	}
	for (i = 0; i < G_N_ELEMENTS(map); i++) {
		if (strcmp(attribute, map[i].name) == 0) {
			switch(map[i].type) {
				case tfvalue:
					b = G_STRUCT_MEMBER_P(info->info,
							      map[i].offset);
					return PyLong_FromLong(*b);
					break;
				case svalue:
					p = G_STRUCT_MEMBER_P(info->info,
							      map[i].offset);
					return PyString_FromString(*p ? *p : "");
					break;
				default:
					return Py_BuildValue("s", "Ouch!  What do you do?");
			}
		}
	}
	return Py_FindMethod(authconfig_methods, self, attribute);
}

static PyTypeObject authInfoObjectType = {
	PyObject_HEAD_INIT(&PyType_Type)	/* inherit from base type */
	0,					/* size of what? */
	"authInfo",				/* name of the type */
	sizeof(struct authInfoObject),		/* size of the structure */
	0,					/* item size? */

	/* Standard methods. */
	(destructor) authInfoObject_destroy,
	(printfunc) NULL,
	(getattrfunc) authInfoObject_getattr,
	(setattrfunc) authInfoObject_setattr,
	(cmpfunc) NULL,
	(reprfunc) authInfoObject_print,

	/* Method tables for specific type categories. */
	(PyNumberMethods *) NULL,		/* Numeric methods. */
	(PySequenceMethods *) NULL,		/* Sequence methods. */
	(PyMappingMethods *) NULL,		/* Mapping methods. */
	(hashfunc) NULL,			/* Dictionary lookup method. */
	(ternaryfunc) NULL,			/* Object-as-operator method. */
	(reprfunc) NULL,			/* Object-as-svalue method. */
};

static PyObject *
authconfig_getusershells(PyObject *self)
{
	const char *p;
	PyObject *ret;
	ret = PyList_New(0);
	setusershell();
	while ((p = getusershell()) != NULL) {
		PyList_Append(ret, PyString_FromString(p));
	}
	endusershell();
	return ret;
}

static struct authInfoObject *
authconfig_read(PyObject *self)
{
	struct authInfoObject *ret = NULL;
	struct authInfoType *info;
	info = authInfoRead();
	ret = PyObject_New(struct authInfoObject, &authInfoObjectType);
	if (ret == NULL) {
		PyErr_SetString(PyExc_TypeError, "error creating object");
		return NULL;
	}
	ret->info = info;
	return ret;
}

static struct authInfoObject *
authconfig_copy(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct authInfoObject *ret = NULL, *info;
	char *keywords[] = {"info", NULL};
	if (authInfoObject_Check(self)) {
		info = (struct authInfoObject *)self;
	} else
	if (PyTuple_Check(args)) {
		if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
						 &authInfoObjectType, &info)) {
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "expected authInfoObject");
		return NULL;
	}
	ret = PyObject_New(struct authInfoObject, &authInfoObjectType);
	if (ret == NULL) {
		PyErr_SetString(PyExc_TypeError, "error creating object");
		return NULL;
	}
	ret->info = authInfoCopy(info->info);
	return ret;
}

static PyObject *
authconfig_write(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct authInfoObject *info = NULL;
	char *keywords[] = {"info", NULL};
	if (authInfoObject_Check(self)) {
		info = (struct authInfoObject *)self;
	} else
	if (PyTuple_Check(args)) {
		if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
						 &authInfoObjectType, &info)) {
			return NULL;
		}
	} else
	if (authInfoObject_Check(args)) {
		info = (struct authInfoObject *)args;
	} else {
		PyErr_SetString(PyExc_TypeError, "expected authInfoObject");
		return NULL;
	}
	if (authInfoWrite(info->info)) {
		return Py_BuildValue("i", 1);
	} else {
		return Py_BuildValue("i", 0);
	}
}

static PyObject *
authconfig_post(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct authInfoObject *info;
	char *keywords[] = {"info", "start_daemons", NULL};
	PyObject *start = NULL;
	if (authInfoObject_Check(self)) {
		info = (struct authInfoObject *)self;
		start = args;
	} else
	if (PyTuple_Check(args)) {
		if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!O", keywords,
						 &authInfoObjectType, &info,
						 &start)) {
			return NULL;
		}
	} else
	if (authInfoObject_Check(args)) {
		info = (struct authInfoObject *)args;
	} else {
		PyErr_SetString(PyExc_TypeError, "expected authInfoObject");
		return NULL;
	}
	authInfoPost(info->info, !((start != NULL) && PyObject_IsTrue(start)));
	return Py_BuildValue("");
}

static PyObject *
authconfig_differs(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct authInfoObject *info, *other;
	char *keywords[] = {"other", NULL};
	gboolean equal;

	if (!authInfoObject_Check(self)) {
		return NULL;
	}

	other = NULL;
	if (PyTuple_Check(args)) {
		if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
						 &authInfoObjectType, &other)) {
			return NULL;
		}
	} else
	if (authInfoObject_Check(args)) {
		other = (struct authInfoObject *)args;
	} else {
		PyErr_SetString(PyExc_TypeError, "expected authInfoObject");
		return NULL;
	}

	info = (struct authInfoObject *) self;
	equal = authInfoDiffers(info->info, other->info);
	if (equal) {
		Py_INCREF(Py_None);
		return Py_None;
	}
	return Py_BuildValue("i", 1);
}

static PyObject *
authconfig_join(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct authInfoObject *info;
	char *keywords[] = {"info", NULL};
	if (authInfoObject_Check(self)) {
		info = (struct authInfoObject *)self;
	} else
	if (PyTuple_Check(args)) {
		if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O",
						 keywords,
						 &authInfoObjectType, &info)) {
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "expected authInfoObject");
		return NULL;
	}
	authInfoJoin(info->info, TRUE);
	return Py_BuildValue("");
}

static PyObject *
authconfig_update(PyObject *self)
{
	struct authInfoObject *info;
	if (authInfoObject_Check(self)) {
		info = (struct authInfoObject *)self;
	} else {
		return NULL;
	}
	authInfoUpdate(info->info);
	return Py_BuildValue("");
}

/* Method table mapping functions to wrappers. */
static PyMethodDef module_methods[] = {
	{"read", (PyCFunction)authconfig_read, METH_NOARGS},
	{"write", (PyCFunction)authconfig_write, METH_VARARGS | METH_KEYWORDS},
	{"post", (PyCFunction)authconfig_post, METH_VARARGS | METH_KEYWORDS},
	{"update", (PyCFunction)authconfig_update, METH_NOARGS},
	{"join", (PyCFunction)authconfig_join, METH_VARARGS | METH_KEYWORDS},
	{"copy", (PyCFunction)authconfig_copy, METH_VARARGS | METH_KEYWORDS},
	{"getusershells", (PyCFunction)authconfig_getusershells, METH_NOARGS},
	{NULL, NULL, 0},
};

/* The module initialization function. */
void
initauthconfig(void)
{
	Py_InitModule("authconfig", module_methods);
}
