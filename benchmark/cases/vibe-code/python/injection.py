# SQL and shell injection, Python. Labels describe the truth about each line.
import os
import subprocess

from sqlalchemy import text


def sql(db, uid, name, rows, x):
    db.execute(f"SELECT * FROM users WHERE id = {uid}")  # expect[VIBE013]
    db.execute("SELECT * FROM users WHERE id = %s" % uid)  # expect[VIBE013]
    db.execute("SELECT * FROM users WHERE id = {}".format(uid))  # expect[VIBE013]
    db.execute("SELECT * FROM users WHERE name = '" + name + "'")  # expect[VIBE013]
    db.executemany(f"INSERT INTO t VALUES ({x})", rows)  # expect[VIBE013]
    db.execute("SELECT * FROM users WHERE id = ?", (uid,))  # safe[VIBE013]
    db.execute("SELECT * FROM users WHERE id = %s", (uid,))  # safe[VIBE013]
    db.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (uid,))  # noisy[VIBE013] constant table name, bound id
    query = f"SELECT * FROM users WHERE id = {uid}"
    db.execute(query)  # miss[VIBE013] string built on the line above
    db.execute(text(f"SELECT * FROM t WHERE id = {uid}"))  # expect[VIBE013] SQLAlchemy text() wrapper


def shell(cmd, path, src, dst, d, archive, use_shell):
    subprocess.run(cmd, shell=True)  # expect[VIBE011]
    subprocess.run(["ls", "-l", path])  # safe[VIBE011]
    subprocess.run(cmd, shell=False)  # safe[VIBE011]
    os.system("rm -rf " + path)  # expect[VIBE012]
    os.system(f"convert {src} {dst}")  # expect[VIBE012]
    os.popen("ls %s" % d)  # expect[VIBE012]
    os.system("make clean")  # safe[VIBE012]
    cmd2 = "tar xf " + archive
    os.system(cmd2)  # miss[VIBE012] command built on the line above
