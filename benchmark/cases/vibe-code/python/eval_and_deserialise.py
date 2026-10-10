# Dynamic code execution and unsafe deserialisation, Python.
import ast
import json
import pickle

import yaml


def dynamic(request, user_input, code_from_db, model, data, df):
    result = eval(request.args["expr"])  # expect[VIBE010]
    value = eval(user_input)  # expect[VIBE010]
    exec(code_from_db)  # expect[VIBE010]
    model.eval()  # safe[VIBE010] PyTorch: switches to inference mode
    parsed = ast.literal_eval(data)  # safe[VIBE010]
    total = eval("2 + 2")  # safe[VIBE010] constant expression
    df.eval("a + b")  # safe[VIBE010] pandas method
    # Never call eval(input) on user data.  safe[VIBE010] just a comment
    return result, value, parsed, total


def deserialise(request, stream, body):
    obj = pickle.loads(request.data)  # expect[VIBE014]
    cfg = yaml.load(stream)  # expect[VIBE015]
    cfg = yaml.load(stream, Loader=yaml.FullLoader)  # expect[VIBE015] FullLoader is not a safe loader
    cfg = yaml.load(stream, Loader=yaml.SafeLoader)  # safe[VIBE015]
    cfg = yaml.safe_load(stream)  # safe[VIBE015]
    cfg = yaml.load(  # noisy[VIBE015] safe loader on the next line
        stream, Loader=yaml.SafeLoader)
    data = json.loads(body)  # safe[VIBE014]
    return obj, cfg, data
