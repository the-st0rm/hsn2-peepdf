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
Created on 2015-03-01

@author: Ibrahim M. El-Sayed (the-st0rm)
'''

import sys
from hsn2objectwrapper import BadValueException
sys.path.append("/opt/hsn2/python/commlib")
from hsn2taskprocessor import HSN2TaskProcessor
from hsn2taskprocessor import ParamException, ProcessingException
from hsn2osadapter import ObjectStoreException
import hsn2objectwrapper as ow
import logging
import os
import time
import tempfile
from PDFCore import PDFParser, vulnsDict
from PDFUtils import vtcheck

class peepdfTaskProcessor(HSN2TaskProcessor):


	def __init__(self,connector,datastore,serviceName,serviceQueue,objectStoreQueue,**extra):
		logging.debug(connector)
		logging.debug(datastore)
		logging.debug(serviceName)
		HSN2TaskProcessor.__init__(self,connector,datastore,serviceName,serviceQueue,objectStoreQueue,**extra)

	def taskProcess(self):
		'''
		Returns a list of warnings (warnings). The current task is available at self.currentTask
		'''
		logging.debug(self.__class__)
		logging.debug(self.currentTask)
		logging.debug(self.objects)
		if len(self.objects) == 0:
			raise ObjectStoreException("Task processing didn't find task object.")

		content = ""
		if self.objects[0].isSet("content"):
			filepath = self.dsAdapter.saveTmp(self.currentTask.job, self.objects[0].content.getKey())
			os.system("chmod 755 %s" %(filepath))


		else:
			raise ParamException("content is missing.")


		#TO-DO recieve parameters from to give it to PDFParse for better results
		for param in self.currentTask.parameters:
			if param.name == "param":
				value = str(param.value)
				if len(value) > 0:
					pass
				break

		self.objects[0].addTime("peepdf_time_start",int(time.time() * 1000))

		


		pdfParser = PDFParser()
		isForceMode = True
		isLooseMode = False
		isManualAnalysis = False
		ret,pdf = pdfParser.parse(filepath, isForceMode, isLooseMode, isManualAnalysis)

		#TO-DO recieve parameters from to give it to PDFParse for better results
		if ret==0:
			self.objects[0].addBool("peepdf_executed_successfully", True)
			self.objects[0].addString("file_SHA1", pdf.getSHA1())
			self.objects[0].addString("peepdf_suspicious_content", str(pdf.getSuspiciousComponents()))
			self.objects[0].addString("peepdf_metadata", str(pdf.getMetadata()))
			self.objects[0].addString("peepdf_javascript", str(pdf.getJavascriptCode()))
			self.objects[0].addTime("peepdf_numStreams", pdf.numStreams)

		else:
			self.objects[0].addBool("peepdf_executed_successfully", False)
			#I should remove all the following add strings once I know how I can handle it from the jsont file
			self.objects[0].addString("file_SHA1", "Error")
			self.objects[0].addString("peepdf_suspicious_content", "Error")
			self.objects[0].addString("peepdf_metadata", "Error")
			self.objects[0].addString("peepdf_javascript", "Error")
			self.objects[0].addTime("peepdf_numStreams", 0)

		self.objects[0].addTime("peepdf_time_stop",int(time.time() * 1000))

		self.dsAdapter.removeTmp(filepath)

		return []
