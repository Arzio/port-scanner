import flask

app = flask.Flask(__name__)

# TODO: CLI integration
@app.route("/scan", methods = ['GET'])
def teste():
    return flask.jsonify(tuple(range(100)))

if __name__ == "__main__":
    app.run()