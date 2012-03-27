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
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
  *
  */

#include "config.h"
#include <Python.h>
#include <resolv.h>
#include <unistd.h>

#define DEFAULT_ASIZE 4096
PyMODINIT_FUNC initacutil(void);

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
		PyList_Append(ret, PyString_FromString(p));
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
	ret = Py_BuildValue("s#", ans, rv);
	free(ans);
	return ret;
}

static PyMethodDef acutil_methods[] = {
	{"res_send",  resolver_send, METH_VARARGS, "Send query to resolver."},
	{"getusershells", getusershells, METH_VARARGS, "List allowed user shells."},
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initacutil(void)
{
    (void)Py_InitModule("acutil", acutil_methods);
}
