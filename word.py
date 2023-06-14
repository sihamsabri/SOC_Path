import subprocess

def macros_analysis(file):
    com = "oleid "+file
    output = subprocess.check_output(com,shell=True).decode("utf-8")

    # Find the line containing "VBA Macros" information
    start_index = output.find("VBA Macros")
    if start_index != -1:
    # Extract the line containing the information
        line = output[start_index:].split("\n")[0]
    # Check if the line contains "Yes, suspicious"
        if "Yes, suspicious" in line:
            result = "Yes, suspicious"
            com0="oledump.py 77b45d70062e2d27973484bfa11f3dc838a579d53d0989ba630bf109316d4684.docx"
            output=subprocess.check_output(com0, shell=True).decode("utf-8")
            lines = output.split('\n')
            macro_lines = []
            for line in lines:
                if 'M' in line:
                    line_number = line.split(':')[0]
                    macro_lines.append(int(line_number))
            if macros_lines!=[]:
                for num in macros_lines:
                    com1="oledump.py -s "+num+" -V"+file
                    out=subprocess.check_output(com1, shell=True).decode("utf-8")
                    malicious_functions = ['AutoOpen', 'Document_Open', 'Workbook_Open']
                    malicious_patterns = ['Shell', 'CreateObject', 'GetObject', 'Run', 'Exec',
                          'ActiveXObject', 'HTTP', 'FTP', 'SendMail', 'RegRead',
                          'RegWrite', 'CreateFile', 'DeleteFile', 'WriteFile',
                          'cmd.exe', 'PowerShell', 'Base64']
                    for function in malicious_functions:
                        if function in out:
                            return("Malicious")
                    for pattern in malicious_patterns:
                        regex_pattern = r"\b" + re.escape(pattern) + r"\b"
                        matches = re.findall(regex_pattern, out, re.IGNORECASE)
                        if matches:
                            return("Malicious Pattern")
        else:
            result = "No"
    # Print the result
        print("VBA Macros:", result)
    else:
        print("VBA Macros information not found in the output.")
file="77b45d70062e2d27973484bfa11f3dc838a579d53d0989ba630bf109316d4684.docx"
macros_analysis(file)
