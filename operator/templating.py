from collections.abc import Mapping
from typing import Any

import jinja2
from str2bool import str2bool

def error_if_undefined(result: Any) -> Any:
    """Handle undefined result as error.
    This allows for use of chainable undefined with default."""
    if isinstance(result, jinja2.Undefined):
        result._fail_with_undefined_error()
    else:
        return result

def bool_filter(value: Any) -> bool:
    if isinstance(value, str):
        return str2bool(value)
    return bool(value)

j2env = jinja2.Environment(
    finalize = error_if_undefined,
    undefined = jinja2.ChainableUndefined,
)

j2env.filters['bool'] = bool_filter
j2template_cache: dict[str, jinja2.Template] = {}

def j2template_get(template: str) -> jinja2.Template:
    if template in j2template_cache:
        return j2template_cache[template]
    j2template = j2env.from_string(template)
    j2template_cache[template] = j2template
    return j2template

def check_condition(condition: str, variables: Mapping[str, Any]) -> bool:
    j2template = j2template_get("{{(" + condition + ")|bool}}")
    return bool(str2bool(j2template.render(variables)))

def process_template(template, variables: Mapping[str, Any]) -> str:
    if '{{' in template or '{%' in template:
        return j2template_get(template).render(variables)
    return template.format(**variables)
