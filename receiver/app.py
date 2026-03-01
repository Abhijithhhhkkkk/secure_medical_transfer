from flask import Flask, render_template, session, redirect, url_for
import os

app = Flask(__name__)
app.secret_key = "secretkey"

DECRYPTED_FOLDER = "static/images"

USERNAME = "admin"
PASSWORD = "1234"

@app.route("/", methods=["GET", "POST"])
def login():
    from flask import request
    if request.method == "POST":
        if request.form.get("username") == USERNAME and request.form.get("password") == PASSWORD:
            session["user"] = USERNAME
            return redirect(url_for("dashboard"))
        else:
            return "Invalid Credentials"
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    images = os.listdir(DECRYPTED_FOLDER)  # only reads already decrypted images
    return render_template("dashboard.html", images=images, user=session["user"])

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)