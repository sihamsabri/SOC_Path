import subprocess

def macros_analysis():
    com = "oleid INTERNSHIP_MaliciousDocumentsAnalysis_PROJECT_DESCRIPTION_20230602.02.docx"
    output = subprocess.check_output(com,shell=True).decode("utf-8")

    # Find the line containing "VBA Macros" information
    start_index = output.find("VBA Macros")
    if start_index != -1:
    # Extract the line containing the information
        line = output[start_index:].split("\n")[0]
    # Check if the line contains "Yes, suspicious"
        if "Yes, suspicious" in line:
            result = "Yes, suspicious"
        else:
            result = "No"
    # Print the result
        print("VBA Macros:", result)
    else:
        print("VBA Macros information not found in the output.")

macros_analysis()
