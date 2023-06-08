import subprocess
import os
import re
from main import *

def pdf_advanced(file):

    # To return in case of a benign file!
    M_result= dict()
    M_result['status'] = '1'
    M_result['result'] = 'Malicious'
    # To return in case of Malicious file!
    B_result= dict()
    B_result['status'] = '0'
    B_result['result'] = 'clean'
    com = "pdfid.py " +file
    output = subprocess.check_output(com,shell=True)
    c = (str(output))[1:]
    Lines = c.split('\\n')

    # count = c.count('\n ')
    Lines.pop(0)
    Lines.pop(0)
    values = {}

    for element in Lines:
        parts = element.split()
        if len(parts) > 1:
            name = parts[0].strip()
            value = parts[1].strip()
            values[name] = int(value) if value.isdigit() else value

    if (values.get('/Encrypt', 0) ==0 and values.get('/Objstm', 0) ==0 and values.get('/JS', 0) ==0 and values.get('/JavaScript', 0) ==0 and values.get('/AA', 0) ==0 and values.get('/Launch', 0) ==0 and values.get('/URI')==0):

        return(B_result)

    if values.get('/Objstm')!=0:
        print()

    if values.get('/JS')!=0:
        js_com = "pdf-parser.py -s JS "+ file+ " > text.txt"
	os.system(js_com)

	with open('text.txt','r') as file:
            file_content=file.read()
	    function_names = ['eval', 'setTimeout', 'setInterval', 'innerHTML', 'Function', 'exec', 'compile', 'open']
	    for function_name in function_names:
                pattern = r'\b{}\b'.format(function_name)
                if re.search(pattern, file_content):
        	    return(M_result)

    if values.get('/JavaScript')!=0:
        jvs_com = "pdf-parser.py -s JavaScript "+ file+ " > text.txt"
	os.system(jvs_com)
	with open('text.txt','r') as file:
            file_content=file.read()
            function_names = ['eval', 'setTimeout', 'setInterval', 'innerHTML', 'Function', 'exec', 'compile', 'open']
            for function_name in function_names:
                pattern = r'\b{}\b'.format(function_name)
                if re.search(pattern, file_content):
                    return(M_result)

		elif shellcode_pattern = r'\\x[a-fA-F0-9]{2}':
		    matches = re.findall(shellcode_pattern, file_content)
		    if matches:
			return(M_result)

    if values.get('/URI')!=0:
        uri_com  = "pdf-parser.py -s URI " + file
	output = subprocess.check_output(uri_com,shell=True)
        c = (str(output))[1:]
	# Here we try to analyze the embedded links in the pdf file !
	# We extract all the urls using regex, then we analyze them !
	url_analysis(c)

    if values.get('/AA')!=0:
        print()

    if values.get('/Launch')!=0:
        print()


pdf_advanced('file1.pdf')
