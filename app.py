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
        
        if 'text' in request.form and 'file' in request.files:
            text=request.form['text']
            file = request.files['file']
            txt= "python3 CAT/URL\ Detection/First_step/main.py "+text
            txt_out= subprocess.check_output(txt, shell=True).decode("utf-8")
            print(txt_out)
            result = "Text Analysis result : "+ txt_out+ "\n"
            file_path = file.filename
            file.save(file_path)
            # Here we get the extension of the file
            file_extension = os.path.splitext(file_path)[1].lower()
            if file_extension == '.pdf':
            
        # Process the file using your Python processing code
        #result = process_file(file)
                com = "python3 pdf_analysis.py "+file_path
                pdf = subprocess.check_output(com, shell=True).decode("utf-8")
                print(pdf)
                result = result + "PDF File Analysis result: "+pdf+ "\n"
            elif file_extension == '.docx':
                com = "python3 word.py "+file_path
                word = subprocess.check_output(com, shell=True)
                print(word)
                result= result + "Word File Analysis result: "+word+"\n"
        # Return the result to the HTML template
            #result = result.decode('utf-8')
            return render_template('result.html', result=result)

    return render_template('upload.html')

if __name__ == '__main__':
    app.run()
