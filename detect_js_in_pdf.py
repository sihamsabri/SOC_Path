import subprocess
import re
import sys

def string_processing(refvar):
    parsing= refvar.replace("\r\n",",")
    new_pars=' '
    for i in range (len(parsing)):
        if (parsing[i]==" " or parsing[i]==",") and parsing[i-1] == ",":
            new_pars = new_pars + ""
        else:
            new_pars = new_pars + parsing[i]


    string=''
    for i in range (len(new_pars)-1):
        if new_pars[i]== "<":
            string += new_pars[:i-1].lstrip()
            break
        else:
            string=new_pars
        
    substrings = string.split("obj")

# Remove any empty strings from the list
    substrings = [substring.strip() for substring in substrings if substring.strip()]

    substrlist = []
# Print the resulting substrings
    for substring in substrings:
        substring = "obj: " + substring.rstrip(",")
        substrlist.append(substring)
   

# Create an empty list to hold the dictionaries
    result = []

# Iterate over the strings and convert them into dictionaries
    for string in substrlist:
    # Remove the "obj:" prefix
        string = string.replace('obj:', '').strip()
    
    # Split the string using commas as the delimiter
        values = string.split(',')
    
    # Create a dictionary with the keys and values
        dictionary = {
            'obj':  values[0],
            'Type': values[1].split(':')[1].strip(),
            'Referencing': values[2].split(':')[1].strip()
        }
    
    # Append the dictionary to the result list
        result.append(dictionary)
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
        com1= "pdf-parser.py "+pdf_file+" --search JS"
        pars = subprocess.check_output(com1,shell=True).decode("utf-8")
        result = string_processing(pars)


# In the following code we're going to extract Javascript code

#If a section of the pdf isn't refrenced by another one then we proceed with the extraction
#In case it's refrenced by another object, then we'll extract instead that object
        
        try:
            count = 0
            for i in result:
                count += 1
                filename = "extract"+str(count)+".txt"
                filenameprime = "extractPr"+str(count)+".txt"
                if i["Referencing"] == "":
                    varob = i["obj"].split(" ")

                    subprocess.check_output([sys.executable, "%s"%self.pdfparser_path, "%s"%self.file_path,"--object", "%s"%varob[0],"--filter","--raw","-d","%s"%filename])

            #this second command is to handle the case where the FlateDecode option isn't used on the object
                    subprocess.check_output([sys.executable, "%s"%self.pdfparser_path, "%s"%self.file_path,"--object", "%s"%varob[0],"--raw","-d","%s"%filenameprime])

#The below section of the handle recusively the search of sections to extract for further analysis
                elif i["Referencing"] != "":
                    var = i["Referencing"].split(" ")
                    refer = var[0]
                    
                    while(refer != ""):
                        
                        refvar = subprocess.check_output([sys.executable, "%s"%self.pdfparser_path, "%s"%self.file_path,"--object","%s"%refer]).decode("utf-8")
                        result_dic = string_processing(refvar)
                        
                        refer_list = result_dic[0]["Referencing"].split(" ")
                        if refer_list == ['']:
                            object_var = (result_dic[0]["obj"].split(" "))[0]
                            subprocess.check_output([sys.executable, "%s"%self.pdfparser_path, "%s"%self.file_path,"--object", "%s"%object_var[0],"--filter","--raw","-d","%s"%filename])

                            #this second command is to handle the case where the FlateDecode option isn't used on the object
                            subprocess.check_output([sys.executable, "%s"%self.pdfparser_path, "%s"%self.file_path,"--object", "%s"%object_var[0],"--raw","-d","%s"%filenameprime])

                        refer = refer_list[0]
                    


        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"An error occurred: {e}")

    
        

# Usage example
pdf_file = "f18652128eed28061610cd1b5c19d5189e3204487934ab67a5d805e0ab64e78b.pdf"
parser_path = "pdf-parser.py"
analyzer = PDFAnalyzer(pdf_file,parser_path)
print(analyzer.detect_javascript_with_pdfparser())

"""javascript_detected_pdfparser = analyzer.detect_javascript_with_pdfparser()
if javascript_detected_pdfparser:
    print("JavaScript code detected in the PDF file (using pdf-parser).")
else:
    print("No JavaScript code found in the PDF file (using pdf-parser).")"""


javascript_patterns = analyzer.detect_javascript_patterns()
print("hi")
for pattern, matched in javascript_patterns.items():
    var = r"alert"
    if matched and (pattern == var):
        print(f"JavaScript pattern '{pattern}' detected in the PDF file.\n This is a malicious PDF")
    elif matched and (pattern != var) :
        print(f"JavaScript pattern '{pattern}' detected in the PDF file.\n This is a suspicious PDF")

