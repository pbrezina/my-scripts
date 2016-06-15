#
# shvfile.py
#
# Implementation of non-destructively reading/writing files containing
# only shell variable declarations and full-line comments.
#
# Copyright 1999 - 2005 Red Hat, Inc.
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#

import os

def read(filename):
	shv = SHVFile()
	shv.open(filename, "r")
	shv.parse()
	return shv

def rcreate(filename):
	shv = SHVFile()
	shv.open(filename, "r+")
	shv.parse()
	return shv

# remove escaped characters in place
def unescape(s):
	if not s:
		return s
	slen = len(s)
	if (s[0] == "\"" or s[0] == "'") and s[0] == s[slen-1]:
		s = s[1:slen-1]
	i = 0
	while True:
		i = s.find("\\", i)
		if i < 0:
			break
		if i+1 >= len(s):
			s = s[0:i]
			break
		s = s[0:i] + s[i+1:]
		i += 1
	return s

# create a new string with all necessary characters escaped.
def escape(s):
	s = s.replace("\\", "\\\\")
	s = s.replace("\"", "\\\"")
	s = s.replace("'", "\\\'")
	s = s.replace("$", "\\\$")
	s = s.replace("~", "\\\~")
	s = s.replace("`", "\\\`")
	if s.find(" ") > 0 or s.find("\t") > 0:
		s = "\"" + s + "\""
	return s

class SHVFile:
	def __init__(self):
		self.filename = ""
		self.f = None
		self.variables = {}
	
	def open(self, filename, mode):
		self.filename = filename
		if mode == "r":
			self.f = open(filename, mode)
		else:
			try:
				self.f = open(filename, mode)
			except IOError:
				pass
		return

	def parse(self):
		if not self.f:
			return
		for line in self.f:
			vs = line.rstrip().split("=",1)
			if len(vs) < 2:
				continue
			self.variables[vs[0]] = unescape(vs[1])

	def write(self, perms):
		if not self.f:
			try:
				fd = os.open(self.filename, os.O_RDWR | os.O_CREAT, perms)
			except OSError:
				return
			try:
				self.f = os.fdopen(fd, "w")
			except IOError:
				os.close(fd)
				return
		try:
			self.f.seek(0)
			self.f.truncate()
			ordereditems = self.variables.items()
			ordereditems.sort(lambda x, y: cmp(x[0], y[0]))
			for name, value in ordereditems:
				self.f.write(name + "=" + escape(value) + "\n")
			self.f.flush()
			os.fsync(self.f.fileno())
		except IOError:
			# we cannot do much in case of error anyway
			pass

	def close(self):
		if self.f:
			try:
				self.f.close()
			except IOError:
				# we cannot do much in case of error anyway
				pass
			self.f = None			

	def getValue(self, name):
		try:
			return self.variables[name]
		except KeyError:
			return ""

	def getBoolValue(self, name):
		# return True if <key> resolves to any truth value (e.g. "yes", "y", "true")
		# return False if <key> resolves to any non-truth value (e.g. "no", "n", "false")
		# raise ValueError otherwise
		try:
			val = self.variables[name].lower()
		except KeyError:
			raise ValueError
		if val == "yes" or val == "true" or val == "t" or val == "y":
			return True
		if val == "no" or val == "false" or val == "f" or val == "n":
			return False
		raise ValueError

	def setValue(self, name, value):
		if not value:
			if name in self.variables:
				del self.variables[name]
		else:
			self.variables[name] = value

	def setBoolValue(self, name, value):
		if value:
			self.variables[name] = "yes"
		else:
			self.variables[name] = "no"
