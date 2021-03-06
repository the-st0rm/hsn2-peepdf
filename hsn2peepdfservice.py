#!/usr/bin/python -tt

# Copyright (c) NASK
# 
# This file is part of HoneySpider Network 2.0.
# 
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''
Created on 2012-07-10

@author: pawelch
'''

import sys
sys.path.append("/opt/hsn2/python/commlib")
from hsn2service import HSN2Service
from hsn2peepdftaskprocessor import peepdfTaskProcessor
from hsn2service import startService
from os import access
from os import path
import logging

class peepdfService(HSN2Service):
	'''
	This is the HSN2 service which utilizes the Peepdf Python low-interaction honeyclient.
	'''

	serviceName = "peepdf"
	description = "HSN 2 Peepdf Service"

	def extraOptions(self,parser):
		'''Arguments specific to this service. Receives a parser with the standard options. Returns a modified parser.'''
		return parser

	def sanityChecks(self, cliargs):
		passed = HSN2Service.sanityChecks(self, cliargs)
		try:
			from PDFCore import PDFParser
		except ImportError:
			passed = False
		return passed

if __name__ == '__main__':
	startService(peepdfService,peepdfTaskProcessor)
