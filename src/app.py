from flask import Flask, request, redirect, render_template, url_for
import os
os.chdir('\\'.join(str(__file__).split("\\")[:-1]))
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    # body = request.values.get('Body', None)
    # text = request.form['From']
    return render_template('index.html')

if __name__ == "__main__":
    app.run(host='localhost', port=1337, debug = True)
