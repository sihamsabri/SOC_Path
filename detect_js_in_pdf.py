import subprocess
import re
import sys


def string_processing(refvar):
    # Split the input string into individual lines
    lines = refvar.split('\n')

    result = []
    obj_data = None

    for line in lines:
        line = line.strip()

        # Check if the line starts with "obj" followed by numbers and whitespace
        if line.startswith("obj") and re.match(r"obj\s+\d+\s+\d+", line):
            if obj_data is not None:
                result.append(obj_data)

            obj_line = line.split()
            obj_num = obj_line[1]
            obj_data = {'obj': obj_num}
        elif line.startswith("Type:"):
            obj_type = line.split(':')[1].strip()
            obj_data['Type'] = obj_type
        elif line.startswith("Referencing:"):
            referencing = line.split(':')[1].strip()
            obj_data['Referencing'] = referencing

    if obj_data is not None:
        result.append(obj_data)

    return result


class PDFAnalyzer:
    def __init__(self, file_path, pdfparser_path):
        self.file_path = file_path
        self.pdfparser_path = pdfparser_path   #mmettre le chemin absolue des fichiers

    #This method is designed to detect malicious js include in plaintext in a pdf file
    def detect_javascript_patterns(self):
    # Define the JavaScript patterns to search for
        patterns = [
        r'\b(eval\()',
        r'\b(document\.cookie\b)',
        r'\b(unescape\()',
        r'\b(setTimeout\()',
        r'\b(setInterval\()',
        r'\b(innerHTML\()',
        r'\b(function\()',
        r'\b(exec\()',
        r'\b(compile\()',
        r'\b(open\()'
        # Add more patterns as needed
        ]

    # Initialize a dictionary to store the pattern matches
        pattern_matches = {pattern: False for pattern in patterns}

    # Open the PDF file in read-binary mode
        with open(self.file_path, 'rb') as file:
        # Read the binary data of the PDF file
            data = file.read()

        # Convert the binary data to a string using Latin-1 encoding
            data_str = data.decode('latin-1')

        # Search for each JavaScript pattern using regular expressions
            for pattern in patterns:
                matches = re.findall(pattern, data_str)

            # If matches are found, update the pattern_matches dictionary
                if matches:
                    pattern_matches[pattern] = True

    # Return the pattern_matches dictionary
        return pattern_matches

    

    def detect_javascript_with_pdfparser(self):

        # To return in case of Malicious file!
        
        M_result= dict()
        M_result['status'] = '1'
        M_result['result'] = 'Malicious'
    # To return in case of a benign file!
        B_result= dict()
        B_result['status'] = '0'
        B_result['result'] = 'clean'
        com = "pdfid.py " +pdf_file
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
        com1= "pdf-parser.py "+pdf_file+" --search JavaScript"
        pars = subprocess.check_output(com1,shell=True).decode("utf-8")
        result = string_processing(pars)
        print(result)
        #result=[{'obj': '1', 'Type': '/Catalog', 'Referencing': '2 0 R'}, {'obj': '7', 'Type': '', 'Referencing': '10 0 R'}, {'obj': '12', 'Type': '', 'Referencing': '13 0 R'}]
# In the following code we're going to extract Javascript code

# If a section of the pdf isn't refrenced by another one then we proceed with the extraction
# In case it's refrenced by another object, then we'll extract instead that object
        
        try:
            count = 0
            for i in result:
                count += 1
                filename = "extract"+str(count)+".txt"
                filenameprime = "extractPr"+str(count)+".txt"
                if i["Referencing"] == "":
                    varob = i["obj"].split(" ")

                    subprocess.check_output([sys.executable, "%s"%self.pdfparser_path, "%s"%self.file_path,"--object", "%s"%varob[0],">","%s"%filename])
                    
#com2="pdfparser.py "+pdf_file+" --object "+varob[0]+" --filter --raw -d "+filename
                    #subprocess.check_output(com2,shell=True)
            # This second command is to handle the case where the FlateDecode option isn't used on the object
                    subprocess.check_output([sys.executable, "%s"%self.pdfparser_path, "%s"%self.file_path,"--object", "%s"%varob[0],">","%s"%filenameprime])

# The below section of the handle recusively the search of sections to extract for further analysis
                elif i["Referencing"] != "":
                    var = i["Referencing"].split(" ")
                    refer = var[0]
                    
                    while(refer != ""):
                        
                        refvar = subprocess.check_output([sys.executable, "%s"%self.pdfparser_path, "%s"%self.file_path,"--object","%s"%refer]).decode("utf-8")
                        result_dic = string_processing(refvar)
                        print("yes")
                        print(result_dic)
                        if len(result_dic) > 0:
                            
                            refer_list = result_dic[0]["Referencing"].split(" ")
                            if refer_list == ['']:
                                object_var = (result_dic[0]["obj"].split(" "))[0]
                                subprocess.check_output([sys.executable, "%s"%self.pdfparser_path, "%s"%self.file_path,"--object", "%s"%object_var[0],">","%s"%filename])

                            # This second command is to handle the case where the FlateDecode option isn't used on the object
                                subprocess.check_output([sys.executable, "%s"%self.pdfparser_path, "%s"%self.file_path,"--object", "%s"%object_var[0],">","%s"%filenameprime])

                            refer = refer_list[0]
                    


        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"An error occurred: {e}")

def Spider_Monk_Analysis(self):
        
        #This first section will look for eval in the output produced by spider monkey, if exist then the js is malicious
        
        directory = os.getcwd()
 
# Regular expression pattern to match encoded shellcode
        pattern = r'\\x[0-9a-fA-F]{2}|%u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}|\u[0-9a-fA-F]{4}|&#x[0-9a-fA-F]{2};'

        for filename in os.listdir(directory):
            if filename.startswith('extract') and os.path.isfile(os.path.join(directory, filename)):
                file_path = os.path.join(directory, filename)
                if os.path.getsize(file_path) > 0:  # Check if file is not empty
                    with open(file_path, 'r') as file:
                        content = file.read()
                        if 'No Filter' not in content:  
                            # Find eval or unscape functions
                            print(f"Processing file: {filename}")
                            if find_mal_js(filename) :
                                return "Malicious Js code detected"
                            # Find matches of encoded shellcode using regular expression
                            matches = re.findall(pattern, content)
                            if matches:
                                print(f"Encoded Shellcode Detected inside the file: {filename}")
                                return("Malicious Js code detected")
                            
                            #We suppose temporaly that the js code is obsfucated so we're doing the deobsfucation with spider monkey now
                            subprocess.check_output([sys.executable, "js","-f","/usr/share/remnux/objects.js","-f","%s"%filename,">", "spider_monk_f.txt"])

                            #we are going to look for shellcode in the deobsfucated file now
                            with open("spider_monk_f.txt", 'r') as shell_file:
                                sc = shell_file.read()
                                shell_match = re.findall(pattern, sc)
                                if shell_match:
                                    print(f"Encoded Shellcode Detected inside the file: {filename}")
                                    return("Malicious Js code detected")
                                
                            # The code below find possible malicious URI in the js code
                                url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
                                extracted_urls = []
                                url_match = re.findall(url_pattern, sc)
                                if url_match:
                                    extracted_urls.extend(url_match)
                                    result_analysis = ""
                                    for i in range (len(extracted_urls)):
                                        result_analysis = url_analysis(i)["raison"]
                                    if result_analysis != "clean link" :
                                        print(f"Malicious link Detected inside the file: {filename}")
                                        return("Malicious Js code detected")
                                
                                #this is for the detection of eventual eval and unscape function in the deobsfucated code 
                                if find_mal_js("spider_monk_f.txt") :
                                    return "Malicious Js code detected"
                                       
        

# Usage example
pdf_file = "f18652128eed28061610cd1b5c19d5189e3204487934ab67a5d805e0ab64e78b.pdf "
parser_path = "/usr/local/bin/pdf-parser.py"
analyzer = PDFAnalyzer(pdf_file,parser_path)
analyzer.detect_javascript_with_pdfparser()

"""javascript_detected_pdfparser = analyzer.detect_javascript_with_pdfparser()
if javascript_detected_pdfparser:
    print("JavaScript code detected in the PDF file (using pdf-parser).")
else:
    print("No JavaScript code found in the PDF file (using pdf-parser).")"""


javascript_patterns = analyzer.detect_javascript_patterns()

if javascript_patterns != {}:
    for pattern, matched in javascript_patterns.items():
        var = r"\b(eval\()"
        if matched and (pattern == var):
            print(f"JavaScript pattern '{pattern}' detected in the PDF file.\n This is a malicious PDF")
        elif matched and (pattern != var) :
            print(f"JavaScript pattern '{pattern}' detected in the PDF file.\n This is a suspicious PDF")
else:
    analyzer.detect_javascript_with_pdfparser()
    print(analyzer.Spider_Monk_Analysis())
