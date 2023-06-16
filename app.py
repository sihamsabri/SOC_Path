from flask import Flask, render_template, request
import subprocess
import os
# Import your Python processing code
#from pdf_analysis import *
app = Flask(__name__, static_folder='static')
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        # Get the uploaded file
        file = request.files['file']
        file_path = file.filename
        file.save(file_path)
        # Here we get the extension of the file
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension == '.pdf':
            
        # Process the file using your Python processing code
        #result = process_file(file)
            com = "python3 pdf_analysis.py "+file_path
            result = subprocess.check_output(com, shell=True)
        elif file_extension == '.docx':
            com = "python3 word.py "+file_path
            result = subprocess.check_output(com, shell=True)
        # Return the result to the HTML template
        result = result.decode('utf-8')
        return render_template('result.html', result=result)

    return render_template('upload.html')

if __name__ == '__main__':
    app.run()
