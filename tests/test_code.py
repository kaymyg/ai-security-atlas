from conftest import ids


def test_llm_output_execution(scan):
    code = (
        "out = client.messages.create(...)\n"
        "exec(out.content[0].text)\n"
        "subprocess.run(completion.choices[0].message.content, shell=True)\n"
    )
    found = ids(scan({"agent.py": code}))
    assert "VIBE001" in found
    assert "VIBE003" in found
    assert "VIBE011" in found


def test_python_exec_is_not_called_a_shell_command(scan):
    findings = scan({"a.py": "exec(completion.text)\n"})
    assert ids(findings) == ["VIBE001"]


def test_user_input_in_system_prompt(scan):
    py = 'system_prompt = f"You help {request.json["name"]}"\n'
    js = "const systemPrompt = `Act as ${req.body.role}`;\n"
    assert "VIBE002" in ids(scan({"a.py": py}))
    assert "VIBE002" in ids(scan({"b.ts": js}))


def test_python_rules(scan):
    code = "\n".join([
        'cur.execute(f"SELECT * FROM t WHERE id={uid}")',
        'cur.execute("SELECT * FROM t WHERE id=%s" % uid)',
        'os.system("rm " + path)',
        "pickle.loads(blob)",
        "yaml.load(fh)",
        "requests.get(url, verify=False)",
        "app.run(debug=True)",
        'open("/data/" + request.args["f"])',
        "session_token = random.choice(chars)",
        "@csrf_exempt",
        "# TODO: add authentication",
    ])
    found = ids(scan({"app.py": code}))
    for rule in ["VIBE012", "VIBE013", "VIBE014", "VIBE015", "VIBE016", "VIBE017", "VIBE018", "VIBE050",
                 "VIBE053", "VIBE054"]:
        assert rule in found, rule


def test_python_safe_versions_are_quiet(scan):
    code = "\n".join([
        'cur.execute("SELECT * FROM t WHERE id=%s", (uid,))',
        "yaml.load(fh, Loader=yaml.SafeLoader)",
        "data = yaml.safe_load(fh)",
        "model.eval()",
        'subprocess.run(["ls", "-l"])',
        "token = secrets.token_urlsafe(32)",
        'eval("1 + 1")',
    ])
    assert scan({"safe.py": code}) == []


def test_js_rules(scan):
    code = "\n".join([
        "eval(userCode)",
        "el.innerHTML = msg",
        "exec(`git checkout ${branch}`)",
        "db.query(`SELECT * FROM t WHERE id = ${id}`)",
        "prisma.$queryRawUnsafe(q)",
        "new https.Agent({ rejectUnauthorized: false })",
        "const apiKey = Math.random().toString(36)",
        'res.setHeader("Access-Control-Allow-Origin", "*")',
    ])
    found = ids(scan({"server.js": code}))
    for rule in ["VIBE030", "VIBE031", "VIBE032", "VIBE033", "VIBE034", "VIBE050", "VIBE052"]:
        assert rule in found, rule


def test_sanitised_html_is_quiet(scan):
    assert scan({"a.js": "el.innerHTML = DOMPurify.sanitize(msg)\n"}) == []


def test_public_env_secret(scan):
    assert "VIBE035" in ids(scan({".env.local.example": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n"}))
    assert scan({"x.ts": "const url = process.env.NEXT_PUBLIC_SUPABASE_URL\n"}) == []
