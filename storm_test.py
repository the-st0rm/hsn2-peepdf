import sys, os, optparse, re, urllib2, datetime, hashlib, traceback
from datetime import datetime
from PDFCore import PDFParser, vulnsDict
from PDFUtils import vtcheck

pdfParser = PDFParser()
isForceMode = True
isLooseMode = False
isManualAnalysis = False
fileName="msf.pdf"
ret,pdf = pdfParser.parse(fileName, isForceMode, isLooseMode, isManualAnalysis)
print dir(pdf)
print pdf.getSHA1()
print pdf.getSuspiciousComponents()
print pdf.getMetadata()
print pdf.getJavascriptCode()
print pdf.numStreams