from flask import Flask, render_template, jsonify
import os

app = Flask(__name__)

def read_alerts():
    alerts = []
    if os.path.exists(r"D:\IDS_Project\alerts.log"):
        with open(r"D:\IDS_Project\alerts.log", "r") as f:
            for line in f.readlines():
                line = line.strip()
                if line:
                    parts = line.split(" | ")
                    if len(parts) == 2:
                        alerts.append({
                            "time": parts[0],
                            "message": parts[1]
                        })
    return alerts

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/alerts")
def get_alerts():
    return jsonify(read_alerts())

if __name__ == "__main__":
    app.run(debug=True)