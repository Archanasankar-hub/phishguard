
from flask import Flask, render_template, request, jsonify
from detector import analyze_message

app = Flask(__name__)


# Home page
@app.route("/")
def home():
    return render_template("index.html")


# Analyze message
@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    message = data.get("message", "")

    if not message.strip():

        return jsonify({
            "error": "Please enter a message or URL."
        }), 400

    result = analyze_message(message)

    return jsonify(result)


import os

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

