import jinja2
from distutils.util import strtobool

def error_if_undefined(result):
    if isinstance(result, jinja2.Undefined):
        result._fail_with_undefined_error()
    else:
        return result

j2env = jinja2.Environment(
    finalize = error_if_undefined,
    undefined = jinja2.ChainableUndefined,
)

j2env.filters['bool'] = lambda x: bool(strtobool(x)) if isinstance(x, str) else bool(x)

def check_condition(condition, variables):
    j2template = j2env.from_string("{{(" + condition + ")|bool}}")
    return bool(strtobool(j2template.render(variables)))
