 /*
  * acutilmodule - python interface to functions missing in standard library
  * Copyright (c) 2005 Red Hat, Inc.
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
  * along with this program; if not, write to the Free Software Foundation,
  * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
  *
  */

#include "config.h"
#include <Python.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <unistd.h>

#if PY_MAJOR_VERSION >= 3
#define IS_PY3K
#define PYBUILD_BYTES "y#"
PyMODINIT_FUNC PyInit_acutil(void);
#else
#define PYBUILD_BYTES "s#"
PyMODINIT_FUNC initacutil(void);
#endif

#define DEFAULT_ASIZE 4096

static PyObject *
getusershells(PyObject *self, PyObject *args)
{
	const char *p;
	PyObject *ret;
	
	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	
	ret = PyList_New(0);
	setusershell();
	while ((p = getusershell()) != NULL) {
		PyList_Append(ret,
#ifdef IS_PY3K
			PyUnicode_FromString(p)
#else
			PyString_FromString(p)
#endif
			);
	}
	endusershell();
	
	return ret;
}

static PyObject *
resolver_send(PyObject *self, PyObject *args)
{
	const unsigned char *req;
	int reqlen;
	int asize;
	int rv;
	unsigned char *ans;
	PyObject *ret;
	
	if (!PyArg_ParseTuple(args, "s#", &req, &reqlen))
		return NULL;
	
	asize = DEFAULT_ASIZE;
	ans = malloc(asize);
	res_init();
	do {
		rv = res_send(req, reqlen, ans, asize);
		if (rv >= asize) {
			asize = rv + DEFAULT_ASIZE;
			free(ans);
			ans = malloc(asize);
			continue;
		}
		break;
	} while (1);

	if (rv < 0) {
                free(ans);
		Py_INCREF(Py_None);
		return Py_None;
	}
	ret = Py_BuildValue(PYBUILD_BYTES, ans, rv);
	free(ans);
	return ret;
}

static PyMethodDef acutil_methods[] = {
	{"res_send",  resolver_send, METH_VARARGS, "Send query to resolver."},
	{"getusershells", getusershells, METH_VARARGS, "List allowed user shells."},
	{NULL, NULL, 0, NULL}
};

#ifdef IS_PY3K
static struct PyModuleDef acutil_def = {
	PyModuleDef_HEAD_INIT,
	"acutil",
	NULL,
	-1,
	acutil_methods,
	NULL,
	NULL,
	NULL,
	NULL
};

PyMODINIT_FUNC
PyInit_acutil(void)
#else
PyMODINIT_FUNC
initacutil(void)
#endif
{
#ifdef IS_PY3K
    return PyModule_Create(&acutil_def);
#else
    (void)Py_InitModule("acutil", acutil_methods);
#endif
}
