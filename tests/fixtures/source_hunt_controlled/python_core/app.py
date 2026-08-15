# CONTROLLED SOURCE HUNT BENCHMARK FIXTURE.
# Source-only evidence: never import, execute, serve, or deploy this file.


class App:
    def route(self, _path):
        def decorate(function):
            return function

        return decorate


app = App()


def sanitize(value):
    return value


def validate(value):
    return value


def resolve(value):
    return value


def escape(value):
    return value


def system(value):
    return value


def render_template_string(value):
    return value


@app.route("/download")
def vulnerable_file(request):
    return open(request.GET["name"]).read()


@app.route("/download-safe")
def guarded_file(request):
    safe_name = resolve(request.GET["name"])
    return open(safe_name).read()


@app.route("/command")
def vulnerable_command(request):
    return system(request.POST["cmd"])


@app.route("/command-safe")
def guarded_command(request):
    safe_cmd = sanitize(request.POST["cmd"])
    return system(safe_cmd)


@app.route("/query")
def vulnerable_query(request, cursor):
    return cursor.execute(request.GET["query"])


@app.route("/query-safe")
def guarded_query(request, cursor):
    safe_query = validate(request.GET["query"])
    return cursor.execute(safe_query)


@app.route("/template")
def vulnerable_template(request):
    return render_template_string(request.POST["template"])


@app.route("/template-safe")
def guarded_template(request):
    safe_template = escape(request.POST["template"])
    return render_template_string(safe_template)
