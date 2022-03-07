import sys
import types

def convert_numeric_to_str(d):
    # print(f"{__file__}.{sys._getframe(  ).f_code.co_name}")
    cur_type = type(d)

    if cur_type == dict:
        for key, value in d.items():
            d[key] = convert_numeric_to_str(value)

    elif cur_type == list:
        for i, el in enumerate(d):
            d[i] = convert_numeric_to_str(el)

    else:
        if cur_type in [int, float]:
            d = str(d)

    return d

def serialize(data):
    # print(f"{__file__}.{sys._getframe(  ).f_code.co_name}")
    if isinstance(data, types.GeneratorType):
        data = list(data)
    return convert_numeric_to_str(data)
